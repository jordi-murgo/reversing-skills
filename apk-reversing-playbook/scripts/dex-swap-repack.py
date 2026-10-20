#!/usr/bin/env python3
"""Replace one DEX entry in an APK without rebuilding resources or signing it."""

from __future__ import annotations

import argparse
from collections import Counter
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import tempfile
import zipfile

BUFFER_SIZE = 1024 * 1024
DEX_ENTRY = re.compile(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex")
SUPPORTED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}


def digest(path: Path) -> tuple[str, int]:
    value = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(BUFFER_SIZE), b""):
            value.update(chunk)
            size += len(chunk)
    return value.hexdigest(), size


def safe_member(name: str) -> bool:
    if not name or "\\" in name or "\x00" in name or name.startswith("/"):
        return False
    stripped = name[:-1] if name.endswith("/") else name
    parts = stripped.split("/")
    return bool(stripped and all(part not in {"", ".", ".."} for part in parts)
                and not re.fullmatch(r"[A-Za-z]:", parts[0]))


def validate_dex(path: Path) -> dict[str, object]:
    size = path.stat().st_size
    if size < 0x70:
        raise ValueError(f"replacement DEX is shorter than its header: {size} bytes")
    with path.open("rb") as stream:
        header = stream.read(0x70)
    if not re.fullmatch(rb"dex\n[0-9]{3}\x00", header[:8]):
        raise ValueError("replacement does not have a recognized DEX magic")
    declared_size, header_size, endian_tag = struct.unpack_from("<III", header, 0x20)
    if declared_size != size:
        raise ValueError(
            f"replacement DEX size mismatch: header={declared_size}, actual={size}"
        )
    if header_size != 0x70:
        raise ValueError(f"replacement DEX header size is not 0x70: {header_size:#x}")
    if endian_tag != 0x12345678:
        raise ValueError(f"replacement DEX endian tag is unsupported: {endian_tag:#x}")
    return {"magic": header[:8].decode("ascii", errors="replace").rstrip("\x00"),
            "bytes": size}


def validate_archive(archive: zipfile.ZipFile, dex_entry: str) -> zipfile.ZipInfo:
    infos = archive.infolist()
    duplicates = sorted(name for name, count in Counter(i.filename for i in infos).items()
                        if count > 1)
    if duplicates:
        raise ValueError(f"APK contains duplicate member names: {duplicates[0]}")
    for info in infos:
        if not safe_member(info.filename):
            raise ValueError(f"APK contains unsafe member: {info.filename}")
        if info.flag_bits & 0x1:
            raise ValueError(f"APK contains encrypted member: {info.filename}")
        if info.compress_type not in SUPPORTED_COMPRESSION:
            raise ValueError(
                f"APK member uses unsupported compression {info.compress_type}: {info.filename}"
            )
    matches = [info for info in infos if info.filename == dex_entry]
    if not matches:
        raise ValueError(f"DEX entry not found in APK: {dex_entry}")
    return matches[0]


def consume_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> None:
    with archive.open(info, "r") as stream:
        for _ in iter(lambda: stream.read(BUFFER_SIZE), b""):
            pass


def repack(apk: Path, replacement: Path, dex_entry: str, temporary: Path) -> dict[str, object]:
    with zipfile.ZipFile(apk, "r") as source:
        target = validate_archive(source, dex_entry)
        entry_count = len(source.infolist())
        consume_member(source, target)
        with zipfile.ZipFile(temporary, "w", allowZip64=True) as output:
            output.comment = source.comment
            for info in source.infolist():
                copied = copy.copy(info)
                with output.open(copied, "w", force_zip64=True) as outgoing:
                    if info.filename == dex_entry:
                        with replacement.open("rb") as incoming:
                            shutil.copyfileobj(incoming, outgoing, BUFFER_SIZE)
                    elif not info.is_dir():
                        with source.open(info, "r") as incoming:
                            shutil.copyfileobj(incoming, outgoing, BUFFER_SIZE)
    return {
        "dex_entry": dex_entry,
        "compression": "stored" if target.compress_type == zipfile.ZIP_STORED else "deflated",
        "entries": entry_count,
    }


def existing_or_symlink(path: Path) -> bool:
    return os.path.lexists(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path, help="original APK; opened read-only")
    parser.add_argument("replacement_dex", type=Path, help="assembled replacement DEX")
    parser.add_argument("--dex-entry", required=True,
                        help="root entry to replace, for example classes2.dex")
    parser.add_argument("--output", required=True, type=Path,
                        help="new unsigned APK path; existing paths are refused")
    parser.add_argument("--authorization-ref", required=True,
                        help="written APK-mutation authorization reference")
    args = parser.parse_args()

    if not DEX_ENTRY.fullmatch(args.dex_entry):
        parser.error("--dex-entry must be classes.dex or classesN.dex with N >= 2")

    for label, supplied in (("APK", args.apk), ("replacement DEX", args.replacement_dex)):
        expanded = supplied.expanduser()
        if expanded.is_symlink():
            raise SystemExit(f"ERR: refusing symlinked {label}: {expanded}")
        if not expanded.is_file():
            raise SystemExit(f"ERR: {label} not found or not a regular file: {expanded}")

    apk = args.apk.expanduser().resolve()
    replacement = args.replacement_dex.expanduser().resolve()
    output = args.output.expanduser().resolve(strict=False)
    if existing_or_symlink(output):
        raise SystemExit(f"ERR: output already exists: {output}")
    if not output.parent.is_dir():
        raise SystemExit(f"ERR: output parent does not exist: {output.parent}")
    if output in {apk, replacement}:
        raise SystemExit("ERR: output must differ from both inputs")

    try:
        dex_facts = validate_dex(replacement)
        apk_hash, apk_size = digest(apk)
        replacement_hash, _ = digest(replacement)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            facts = repack(apk, replacement, args.dex_entry, temporary)
            output_hash, output_size = digest(temporary)
            os.link(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        raise SystemExit(f"ERR: {error}") from error

    report = {
        "authorization_ref": args.authorization_ref,
        "input": {"path": str(apk), "sha256": apk_hash, "bytes": apk_size},
        "replacement": {"path": str(replacement), "sha256": replacement_hash, **dex_facts},
        "output": {"path": str(output), "sha256": output_hash, "bytes": output_size,
                   "signing": "required"},
        **facts,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
