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
MAX_ARCHIVE_ENTRIES = 100_000
MAX_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
MAX_AGGREGATE_BYTES = 8 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 2000
ZIP64_THRESHOLD = (1 << 31) - 1


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
                and not re.match(r"^[A-Za-z]:", parts[0]))


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


def validate_archive(archive: zipfile.ZipFile, dex_entry: str, max_entries: int,
                     max_member_bytes: int, max_aggregate_bytes: int,
                     max_compression_ratio: int) -> zipfile.ZipInfo:
    infos = archive.infolist()
    if len(infos) > max_entries:
        raise ValueError(f"APK exceeds {max_entries} entries: {len(infos)}")
    duplicates = sorted(name for name, count in Counter(i.filename for i in infos).items()
                        if count > 1)
    if duplicates:
        raise ValueError(f"APK contains duplicate member names: {duplicates[0]}")
    expanded = 0
    for info in infos:
        if not safe_member(info.filename):
            raise ValueError(f"APK contains unsafe member: {info.filename}")
        if info.flag_bits & 0x1:
            raise ValueError(f"APK contains encrypted member: {info.filename}")
        if info.compress_type not in SUPPORTED_COMPRESSION:
            raise ValueError(
                f"APK member uses unsupported compression {info.compress_type}: {info.filename}"
            )
        if info.file_size > max_member_bytes:
            raise ValueError(
                f"APK member exceeds {max_member_bytes} bytes: {info.filename}"
            )
        if info.file_size / max(info.compress_size, 1) > max_compression_ratio:
            raise ValueError(
                f"APK member compression ratio exceeds {max_compression_ratio}: {info.filename}"
            )
        expanded += info.file_size
        if expanded > max_aggregate_bytes:
            raise ValueError(f"APK exceeds {max_aggregate_bytes} aggregate bytes")
    matches = [info for info in infos if info.filename == dex_entry]
    if not matches:
        raise ValueError(f"DEX entry not found in APK: {dex_entry}")
    return matches[0]


def consume_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> None:
    with archive.open(info, "r") as stream:
        for _ in iter(lambda: stream.read(BUFFER_SIZE), b""):
            pass


def repack(apk: Path, replacement: Path, dex_entry: str, temporary: Path,
           max_entries: int, max_member_bytes: int, max_aggregate_bytes: int,
           max_compression_ratio: int) -> dict[str, object]:
    replacement_size = replacement.stat().st_size
    if replacement_size > max_member_bytes:
        raise ValueError(f"replacement DEX exceeds {max_member_bytes} bytes")
    with zipfile.ZipFile(apk, "r") as source:
        target = validate_archive(
            source, dex_entry, max_entries, max_member_bytes,
            max_aggregate_bytes, max_compression_ratio,
        )
        infos = source.infolist()
        entry_count = len(infos)
        output_expanded = sum(info.file_size for info in infos) - target.file_size + replacement_size
        if output_expanded > max_aggregate_bytes:
            raise ValueError(f"output APK exceeds {max_aggregate_bytes} aggregate bytes")
        consume_member(source, target)
        with zipfile.ZipFile(temporary, "w", allowZip64=True) as output:
            output.comment = source.comment
            for info in infos:
                copied = copy.copy(info)
                expected_size = replacement_size if info.filename == dex_entry else info.file_size
                copied.file_size = expected_size
                with output.open(
                    copied, "w", force_zip64=expected_size >= ZIP64_THRESHOLD
                ) as outgoing:
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
    parser.add_argument("--max-entries", type=int, default=MAX_ARCHIVE_ENTRIES)
    parser.add_argument("--max-member-bytes", type=int, default=MAX_MEMBER_BYTES)
    parser.add_argument("--max-aggregate-bytes", type=int, default=MAX_AGGREGATE_BYTES)
    parser.add_argument("--max-compression-ratio", type=int, default=MAX_COMPRESSION_RATIO)
    args = parser.parse_args()

    if not DEX_ENTRY.fullmatch(args.dex_entry):
        parser.error("--dex-entry must be classes.dex or classesN.dex with N >= 2")
    for option in ("max_entries", "max_member_bytes", "max_aggregate_bytes",
                   "max_compression_ratio"):
        if getattr(args, option) <= 0:
            parser.error(f"--{option.replace('_', '-')} must be positive")

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
            facts = repack(
                apk, replacement, args.dex_entry, temporary,
                args.max_entries, args.max_member_bytes,
                args.max_aggregate_bytes, args.max_compression_ratio,
            )
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
