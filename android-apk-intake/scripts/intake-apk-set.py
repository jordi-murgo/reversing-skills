#!/usr/bin/env python3
"""Create a content-addressed evidence manifest for an APK or split-APK set."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import zipfile

ARCHIVE_SUFFIXES = {".apks", ".xapk", ".apkm", ".zip"}


def digest(path: Path) -> tuple[str, int]:
    value = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            value.update(chunk)
    return value.hexdigest(), size


def safe_member(name: str) -> bool:
    member = PurePosixPath(name)
    return bool(name and not member.is_absolute() and ".." not in member.parts)


def sdk_tool(name: str) -> str | None:
    explicit = os.environ.get(name.upper())
    if explicit and Path(explicit).is_file():
        return explicit
    found = shutil.which(name)
    if found:
        return found
    candidates: list[Path] = []
    for variable in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.environ.get(variable)
        if root:
            candidates.extend(Path(root).glob(f"build-tools/*/{name}"))
    return str(sorted(candidates)[-1]) if candidates else None


def apksigner_command() -> list[str] | None:
    jar = os.environ.get("APKSIGNER_JAR")
    if jar and Path(jar).is_file() and shutil.which("java"):
        return [shutil.which("java") or "java", "-jar", jar]
    tool = sdk_tool("apksigner")
    return [tool] if tool else None


def extract_archive(source: Path, destination: Path) -> list[Path]:
    apks: list[Path] = []
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            if not safe_member(info.filename):
                raise ValueError(f"unsafe archive member: {info.filename}")
            if info.is_dir() or PurePosixPath(info.filename).suffix.lower() != ".apk":
                continue
            target = destination.joinpath(*PurePosixPath(info.filename).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as incoming, target.open("xb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)
            apks.append(target)
    return sorted(apks)


def collect_apks(source: Path, staging: Path) -> tuple[str, list[Path]]:
    if source.is_dir():
        escaped = sorted(
            path for path in source.rglob("*.apk")
            if path.is_file() and path.is_symlink()
        )
        if escaped:
            raise ValueError(f"refusing symlinked APK input: {escaped[0]}")
        apks = sorted(path for path in source.rglob("*.apk") if path.is_file())
        return "directory", apks
    suffix = source.suffix.lower()
    if suffix == ".apk":
        return "apk", [source]
    if suffix in ARCHIVE_SUFFIXES:
        return "archive", extract_archive(source, staging)
    raise ValueError("source must be an APK, APK-set archive, or directory")

def pull_installed_package(
    package: str, staging: Path, adb: str, device: str | None
) -> list[Path]:
    prefix = [adb]
    if device:
        prefix.extend(["-s", device])
    code, output = run([*prefix, "shell", "pm", "path", package])
    if code != 0:
        raise ValueError(f"adb pm path failed: {output}")
    remote_paths = [
        line.removeprefix("package:").strip()
        for line in output.splitlines()
        if line.startswith("package:")
    ]
    if not remote_paths:
        raise ValueError(f"no installed APK paths reported for {package}")
    apks: list[Path] = []
    for index, remote in enumerate(remote_paths, start=1):
        filename = re.sub(r"[^A-Za-z0-9._-]", "_", PurePosixPath(remote).name)
        target = staging / f"{index:03d}-{filename}"
        pull_code, pull_output = run([*prefix, "pull", remote, str(target)])
        if pull_code != 0 or not target.is_file():
            raise ValueError(f"adb pull failed for {remote}: {pull_output}")
        apks.append(target)
    return apks


def run(command: list[str]) -> tuple[int, str]:
    process = subprocess.run(command, text=True, capture_output=True, check=False)
    return process.returncode, (process.stdout + process.stderr).strip()


def signer_facts(path: Path, command: list[str] | None) -> dict[str, object]:
    if not command:
        return {"status": "unknown", "reason": "apksigner unavailable", "cert_sha256": []}
    code, output = run([*command, "verify", "--verbose", "--print-certs", str(path)])
    certificates = sorted(set(re.findall(
        r"certificate SHA-256 digest:\s*([0-9a-fA-F:]+)", output, re.IGNORECASE
    )))
    return {
        "status": "verified" if code == 0 else "failed",
        "exit_code": code,
        "cert_sha256": [value.replace(":", "").lower() for value in certificates],
        "output": output,
    }


def package_facts(path: Path, aapt2: str | None) -> dict[str, object]:
    if not aapt2:
        return {"status": "unknown", "reason": "aapt2 unavailable"}
    code, output = run([aapt2, "dump", "badging", str(path)])
    package = re.search(r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'", output)
    split = re.search(r"split='([^']+)'", output)
    return {
        "status": "observed" if code == 0 else "failed",
        "exit_code": code,
        "package": package.group(1) if package else None,
        "version_code": package.group(2) if package else None,
        "version_name": package.group(3) if package else None,
        "split": split.group(1) if split else None,
        "output": output,
    }

def archive_facts(path: Path) -> dict[str, object]:
    try:
        with zipfile.ZipFile(path) as archive:
            corrupt_member = archive.testzip()
            names = archive.namelist()
    except (OSError, zipfile.BadZipFile) as error:
        return {
            "status": "failed", "error": str(error), "dex_entries": [],
            "abis": [], "native_libraries": [],
        }
    dex_entries = sorted(
        name for name in names if re.fullmatch(r"classes([0-9]+)?\.dex", name)
    )
    native_libraries = sorted(
        name for name in names if re.fullmatch(r"lib/[^/]+/[^/]+\.so", name)
    )
    abis = sorted({name.split("/")[1] for name in native_libraries})
    return {
        "status": "valid" if corrupt_member is None else "failed",
        "corrupt_member": corrupt_member,
        "dex_entries": dex_entries,
        "abis": abis,
        "native_libraries": native_libraries,
    }


def normalized_name(index: int, path: Path) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", path.name)
    return f"{index:03d}-{safe}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", nargs="?", type=Path)
    parser.add_argument("--package", help="installed package name to pull through adb")
    parser.add_argument("--device", help="adb device serial")
    parser.add_argument("--adb", default=shutil.which("adb") or "adb")
    parser.add_argument("--output", type=Path, required=True,
                        help="new output directory; existing paths are refused")
    parser.add_argument("--authorization-ref", required=True,
                        help="written scope/authorization reference")
    parser.add_argument("--label", default="authorized-analysis")
    args = parser.parse_args()

    if bool(args.source) == bool(args.package):
        parser.error("provide exactly one source path or --package")
    output = args.output.expanduser().resolve()
    if output.exists():
        raise SystemExit(f"ERR: output already exists: {output}")

    with tempfile.TemporaryDirectory(prefix="apk-intake-") as temporary:
        staging = Path(temporary)
        if args.package:
            if not shutil.which(args.adb) and not Path(args.adb).is_file():
                raise SystemExit(f"ERR: adb unavailable: {args.adb}")
            kind = "installed-package"
            source_identity = f"package:{args.package}"
            apks = pull_installed_package(args.package, staging, args.adb, args.device)
        else:
            source = args.source.expanduser()
            if source.is_symlink():
                raise SystemExit(f"ERR: refusing symlinked input: {source}")
            source = source.resolve()
            if not source.exists():
                raise SystemExit(f"ERR: source not found: {source}")
            kind, apks = collect_apks(source, staging)
            source_identity = str(source)
        if not apks:
            raise SystemExit("ERR: no APKs found")
        output.mkdir(parents=True)
        artifact_dir = output / "artifacts"
        artifact_dir.mkdir()
        signer = apksigner_command()
        aapt2 = sdk_tool("aapt2")
        records: list[dict[str, object]] = []
        for index, apk in enumerate(apks, start=1):
            target = artifact_dir / normalized_name(index, apk)
            shutil.copyfile(apk, target)
            value, size = digest(target)
            records.append({
                "file": str(target.relative_to(output)),
                "original_name": apk.name,
                "sha256": value,
                "bytes": size,
                "archive": archive_facts(target),
                "signing": signer_facts(target, signer),
                "package": package_facts(target, aapt2),
            })

    package_names = sorted({
        record["package"].get("package") for record in records
        if record["package"].get("package")
    })
    verified_records = [
        record for record in records if record["signing"].get("status") == "verified"
    ]
    signer_sets = sorted({
        tuple(record["signing"].get("cert_sha256", [])) for record in verified_records
    })
    signer_consistent = (
        len(signer_sets) == 1 if len(verified_records) == len(records) else None
    )
    set_consistency = (
        "inconsistent" if len(package_names) > 1 or signer_consistent is False else
        "consistent" if len(package_names) == 1 and signer_consistent is True else
        "unknown"
    )
    manifest = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "authorization_ref": args.authorization_ref,
        "label": args.label,
        "source": {"path": source_identity, "kind": kind, "device": args.device},
        "tools": {
            "aapt2": aapt2,
            "apksigner": " ".join(signer) if signer else None,
        },
        "summary": {
            "apk_count": len(records),
            "package_names": package_names,
            "verified_signer_set_count": len(signer_sets),
            "signer_consistent": signer_consistent,
            "set_consistency": set_consistency,
        },
        "artifacts": records,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"manifest={output / 'manifest.json'}")
    print(f"apk_count={len(records)}")
    print(f"set_consistency={set_consistency}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
