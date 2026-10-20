#!/usr/bin/env python3
"""Rank packed or protection-runtime native libraries without executing target code."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile

INTERESTING_IMPORTS = (
    "mmap", "mprotect", "mincore", "dladdr", "dl_iterate_phdr",
    "prctl", "strtoull", "syscall", "getauxval",
)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def elf_identity(data: bytes) -> dict[str, object]:
    result: dict[str, object] = {
        "elf": data.startswith(b"\x7fELF"), "class_bits": None,
        "endianness": None, "machine": None, "entry": None,
    }
    if not result["elf"] or len(data) < 64:
        return result
    elf_class, elf_data = data[4], data[5]
    result["class_bits"] = {1: 32, 2: 64}.get(elf_class)
    result["endianness"] = {1: "little", 2: "big"}.get(elf_data)
    if elf_class != 2 or elf_data not in (1, 2):
        return result
    order = "<" if elf_data == 1 else ">"
    result["machine"] = struct.unpack_from(order + "H", data, 18)[0]
    result["entry"] = struct.unpack_from(order + "Q", data, 24)[0]
    return result


def readelf_facts(path: Path) -> dict[str, object]:
    tool = shutil.which("readelf")
    if not tool:
        return {"readelf_available": False, "soname": None, "jni_onload": 0,
                "register_natives": 0, "imports": []}
    dynamic = subprocess.run([tool, "-d", "-W", str(path)], text=True,
                             capture_output=True, check=False)
    symbols = subprocess.run([tool, "--dyn-syms", "-W", str(path)], text=True,
                             capture_output=True, check=False)
    soname = re.search(r"\(SONAME\).*\[([^]]+)]", dynamic.stdout)
    return {
        "readelf_available": True,
        "soname": soname.group(1) if soname else None,
        "jni_onload": len(re.findall(r"\bJNI_OnLoad\b", symbols.stdout)),
        "register_natives": len(re.findall(r"\bRegisterNatives\b", symbols.stdout)),
        "imports": [name for name in INTERESTING_IMPORTS
                    if re.search(rf"\b{re.escape(name)}\b", symbols.stdout)],
        "readelf_error": (dynamic.stderr + symbols.stderr).strip() or None,
    }


def inspect_library(data: bytes, source: str, temp_dir: Path) -> dict[str, object]:
    identity = elf_identity(data)
    windows = [entropy(data[offset:offset + 4096]) for offset in range(0, len(data), 4096)]
    high_windows = sum(value >= 7.8 for value in windows)
    prologues = 0
    if identity["endianness"] == "little" and identity["machine"] == 183:
        for offset in range(0, max(0, len(data) - 3), 4):
            word = struct.unpack_from("<I", data, offset)[0]
            if word & 0xFFC003FF == 0xA98003FD:
                prologues += 1

    temporary = temp_dir / f"{sha256(data)}.so"
    temporary.write_bytes(data)
    native = readelf_facts(temporary)
    reasons: list[str] = []
    weak_signals: list[str] = []
    score = 0
    if native["soname"] == "libandroid_native_component.so":
        reasons.append("canonical GuardIT SONAME")
        score += 4
    if identity["entry"] == 0:
        weak_signals.append("ELF entry is zero (common for ordinary shared libraries)")
    if windows and high_windows / len(windows) >= 0.5:
        reasons.append("at least half of 4 KiB windows have entropy >= 7.8")
        score += 2
    if identity["machine"] == 183 and prologues <= 5:
        reasons.append("very few plausible ARM64 frame prologues")
        score += 1
    if native["jni_onload"]:
        reasons.append("exports JNI_OnLoad")
        score += 1
    if len(native["imports"]) >= 3:
        reasons.append("imports multiple unpacking/self-inspection APIs")
        score += 2

    return {
        "source": source, "sha256": sha256(data), "bytes": len(data), **identity,
        "entropy": {
            "whole_file": round(entropy(data), 5), "window_size": 4096,
            "window_count": len(windows), "high_entropy_windows": high_windows,
            "high_entropy_fraction": round(high_windows / len(windows), 5) if windows else 0,
            "minimum_window": round(min(windows), 5) if windows else None,
            "maximum_window": round(max(windows), 5) if windows else None,
        },
        "arm64_prologue_count": prologues, **native,
        "candidate_score": score, "candidate_reasons": reasons,
        "weak_signals": weak_signals,
    }


def collect(input_path: Path) -> list[tuple[str, bytes]]:
    if input_path.is_symlink():
        raise SystemExit(f"ERR: refusing symlinked input: {input_path}")
    if input_path.is_file() and input_path.suffix.lower() == ".so":
        return [(str(input_path.resolve()), input_path.read_bytes())]
    if input_path.is_file() and input_path.suffix.lower() == ".apk":
        apks = [input_path]
    elif input_path.is_dir():
        result = []
        for path in sorted(input_path.rglob("*")):
            if path.is_symlink():
                raise SystemExit(f"ERR: refusing symlinked input: {path}")
        for path in sorted(input_path.rglob("*.so")):
            if path.is_file():
                result.append((str(path.resolve()), path.read_bytes()))
        for apk in sorted(input_path.rglob("*.apk")):
            result.extend(collect(apk))
        return result
    else:
        raise SystemExit("ERR: input must be an APK, SO, or directory")
    result: list[tuple[str, bytes]] = []
    for apk in apks:
        with zipfile.ZipFile(apk) as package:
            for name in sorted(package.namelist()):
                if re.fullmatch(r"lib/[^/]+/[^/]+\.so", name):
                    result.append((f"{apk.resolve()}!/{name}", package.read(name)))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, help="new JSON report path; stdout otherwise")
    args = parser.parse_args()
    if not args.input.exists():
        raise SystemExit(f"ERR: input not found: {args.input}")
    libraries = collect(args.input)
    if not libraries:
        raise SystemExit("ERR: no native libraries found")
    with tempfile.TemporaryDirectory(prefix="native-triage-") as temporary:
        records = [inspect_library(data, source, Path(temporary)) for source, data in libraries]
    records.sort(key=lambda record: (-record["candidate_score"], record["source"]))
    report = {
        "schema_version": 1, "input": str(args.input.resolve()),
        "library_count": len(records),
        "heuristic_notice": "Ranking is triage evidence, not proof of vendor identity or successful unpacking.",
        "libraries": records,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        if args.output.exists():
            raise SystemExit(f"ERR: output already exists: {args.output}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"report={args.output.resolve()}")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
