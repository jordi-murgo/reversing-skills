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
import secrets
import shutil
import stat
import struct
import sys
import tempfile
import unicodedata
import zipfile
from typing import BinaryIO

BUFFER_SIZE = 1024 * 1024
DEX_ENTRY = re.compile(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex")
SUPPORTED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
MAX_ARCHIVE_ENTRIES = 100_000
MAX_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
MAX_AGGREGATE_BYTES = 8 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 2000
ZIP64_THRESHOLD = (1 << 31) - 1
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAX_CENTRAL_DIRECTORY_BYTES = 256 * 1024 * 1024
EOCD_SIGNATURE = b"PK\x05\x06"
ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
EOCD = struct.Struct("<4s4H2LH")
ZIP64_EOCD = struct.Struct("<4sQ2H2L4Q")
ZIP64_LOCATOR = struct.Struct("<4sLQL")
CENTRAL_DIRECTORY_HEADER = struct.Struct("<4s6H3L5H2L")


def digest_stream(stream: BinaryIO) -> tuple[str, int]:
    value = hashlib.sha256()
    size = 0
    stream.seek(0)
    for chunk in iter(lambda: stream.read(BUFFER_SIZE), b""):
        value.update(chunk)
        size += len(chunk)
    return value.hexdigest(), size


def safe_message(value: object) -> str:
    return ascii(str(value))[1:-1]

class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {safe_message(message)}\n")

def snapshot_input(source: Path, destination: Path, max_bytes: int) -> tuple[str, int]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("host does not provide O_NOFOLLOW for immutable input snapshots")
    flags = (os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
             | getattr(os, "O_CLOEXEC", 0))
    descriptor = os.open(source, flags)
    value = hashlib.sha256()
    size = 0
    with os.fdopen(descriptor, "rb") as incoming, destination.open("xb") as outgoing:
        if not stat.S_ISREG(os.fstat(incoming.fileno()).st_mode):
            raise ValueError(f"input is not a regular file: {source}")
        for chunk in iter(lambda: incoming.read(BUFFER_SIZE), b""):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"input exceeds {max_bytes} bytes: {source}")
            value.update(chunk)
            outgoing.write(chunk)
    return value.hexdigest(), size


def safe_member(name: str) -> bool:
    if (not name or "\\" in name or "\x00" in name or name.startswith("/")
            or any(unicodedata.category(character) in {"Cc", "Cf"}
                   for character in name)):
        return False
    stripped = name[:-1] if name.endswith("/") else name
    parts = stripped.split("/")
    return bool(stripped and all(part not in {"", ".", ".."} for part in parts)
                and not re.match(r"^[A-Za-z]:", parts[0]))



def preflight_zip(path: Path, max_entries: int,
                  max_central_directory_bytes: int) -> None:
    file_size = path.stat().st_size
    if file_size < EOCD.size:
        raise ValueError("APK is shorter than a ZIP end record")
    tail_size = min(file_size, EOCD.size + 65_535 + ZIP64_LOCATOR.size)
    with path.open("rb") as stream:
        stream.seek(file_size - tail_size)
        tail = stream.read(tail_size)
        position = tail.rfind(EOCD_SIGNATURE)
        if position < 0 or position + EOCD.size > len(tail):
            raise ValueError("APK has no valid ZIP end record")
        fields = EOCD.unpack_from(tail, position)
        if position + EOCD.size + fields[-1] != len(tail):
            raise ValueError("last APK ZIP end-record signature is malformed")

        eocd_offset = file_size - tail_size + position
        (_, disk, central_disk, disk_entries, total_entries,
         central_size, central_offset, _) = fields
        classic_values = (
            disk_entries, total_entries, central_size, central_offset
        )
        sentinels = (0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
        uses_zip64 = any(value == sentinel
                         for value, sentinel in zip(classic_values, sentinels))

        locator_offset = eocd_offset - ZIP64_LOCATOR.size
        locator = b""
        if locator_offset >= 0:
            stream.seek(locator_offset)
            locator = stream.read(ZIP64_LOCATOR.size)
        locator_present = locator.startswith(ZIP64_LOCATOR_SIGNATURE)
        boundary = eocd_offset

        if locator_present:
            if not uses_zip64:
                raise ValueError("APK has noncanonical ZIP64 metadata")
            signature, zip64_disk, zip64_offset, total_disks = ZIP64_LOCATOR.unpack(
                locator
            )
            if signature != ZIP64_LOCATOR_SIGNATURE or zip64_disk != 0 or total_disks != 1:
                raise ValueError("APK has an invalid or multi-disk ZIP64 locator")
            stream.seek(zip64_offset)
            record = stream.read(ZIP64_EOCD.size)
            if len(record) != ZIP64_EOCD.size:
                raise ValueError("APK ZIP64 end record is truncated")
            (signature, record_size, _, _, zip_disk, zip_central_disk,
             zip_disk_entries, zip_total_entries, zip_central_size,
             zip_central_offset) = ZIP64_EOCD.unpack(record)
            if (signature != ZIP64_EOCD_SIGNATURE or record_size < 44
                    or zip64_offset + 12 + record_size != locator_offset):
                raise ValueError("APK ZIP64 end record is noncanonical")
            zip_values = (
                zip_disk_entries, zip_total_entries,
                zip_central_size, zip_central_offset,
            )
            for classic, sentinel, resolved in zip(
                    classic_values, sentinels, zip_values):
                if classic != sentinel and classic != resolved:
                    raise ValueError("APK classic and ZIP64 metadata disagree")
            disk, central_disk = zip_disk, zip_central_disk
            disk_entries, total_entries = zip_disk_entries, zip_total_entries
            central_size, central_offset = zip_central_size, zip_central_offset
            boundary = zip64_offset
        elif uses_zip64:
            raise ValueError("APK ZIP64 locator is missing")

        if disk != 0 or central_disk != 0 or disk_entries != total_entries:
            raise ValueError("multi-disk APK ZIPs are unsupported")
        if total_entries > max_entries:
            raise ValueError(f"APK exceeds {max_entries} entries: {total_entries}")
        if central_size > max_central_directory_bytes:
            raise ValueError(
                f"APK central directory exceeds {max_central_directory_bytes} bytes"
            )
        if central_offset + central_size != boundary:
            raise ValueError("APK central directory does not end at its metadata boundary")

        stream.seek(central_offset)
        remaining = central_size
        observed_entries = 0
        while remaining:
            if remaining < CENTRAL_DIRECTORY_HEADER.size:
                raise ValueError("APK central directory record is truncated")
            header = stream.read(CENTRAL_DIRECTORY_HEADER.size)
            if len(header) != CENTRAL_DIRECTORY_HEADER.size:
                raise ValueError("APK central directory is truncated")
            fields = CENTRAL_DIRECTORY_HEADER.unpack(header)
            if fields[0] != b"PK\x01\x02":
                raise ValueError("APK central directory has an invalid record signature")
            variable_size = fields[10] + fields[11] + fields[12]
            record_size = CENTRAL_DIRECTORY_HEADER.size + variable_size
            if record_size > remaining:
                raise ValueError("APK central directory record exceeds its boundary")
            stream.seek(variable_size, os.SEEK_CUR)
            remaining -= record_size
            observed_entries += 1
            if observed_entries > max_entries:
                raise ValueError(f"APK exceeds {max_entries} entries")
        if observed_entries != total_entries:
            raise ValueError(
                "APK central directory entry count disagrees with its end record"
            )
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
        raise ValueError(f"APK contains duplicate member names: {duplicates[0]!a}")
    expanded = 0
    for info in infos:
        if not safe_member(info.filename):
            raise ValueError(f"APK contains unsafe member: {info.filename!a}")
        if info.flag_bits & 0x1:
            raise ValueError(f"APK contains encrypted member: {info.filename!a}")
        if info.compress_type not in SUPPORTED_COMPRESSION:
            raise ValueError(
                f"APK member uses unsupported compression {info.compress_type}: "
                f"{info.filename!a}"
            )
        if info.file_size > max_member_bytes:
            raise ValueError(
                f"APK member exceeds {max_member_bytes} bytes: {info.filename!a}"
            )
        if info.file_size / max(info.compress_size, 1) > max_compression_ratio:
            raise ValueError(
                f"APK member compression ratio exceeds {max_compression_ratio}: "
                f"{info.filename!a}"
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


def repack(apk: Path, replacement: Path, dex_entry: str, temporary: BinaryIO,
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


def resolve_new_output(supplied: Path) -> tuple[Path, int]:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("host lacks descriptor-safe output primitives")
    expanded = supplied.expanduser()
    if not expanded.name:
        raise ValueError(f"output must name a file: {expanded}")
    parent = expanded.parent.resolve(strict=True)
    expected = os.stat(parent, follow_symlinks=False)
    if not stat.S_ISDIR(expected.st_mode):
        raise ValueError(f"output parent is not a directory: {parent}")
    descriptor = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise RuntimeError("output parent changed while opening")
        try:
            os.stat(expanded.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError(f"output already exists: {parent / expanded.name}")
    except BaseException:
        os.close(descriptor)
        raise
    return parent / expanded.name, descriptor

def create_temporary(parent_descriptor: int) -> tuple[str, int]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("host does not provide O_NOFOLLOW for temporary output")
    flags = (os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
             | getattr(os, "O_CLOEXEC", 0))
    for _ in range(128):
        name = f".dex-swap-{secrets.token_hex(12)}.tmp"
        try:
            return name, os.open(name, flags, 0o600, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
    raise RuntimeError("could not allocate a unique temporary output")


def verify_output_parent(parent_descriptor: int, output: Path) -> None:
    expected = os.fstat(parent_descriptor)
    current = os.stat(output.parent, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
        raise RuntimeError("output parent pathname was replaced")


def publish_temporary(parent_descriptor: int, temporary_name: str,
                      output: Path, descriptor: int) -> None:
    verify_output_parent(parent_descriptor, output)
    expected = os.fstat(descriptor)
    temporary = os.stat(
        temporary_name, dir_fd=parent_descriptor, follow_symlinks=False
    )
    if (temporary.st_dev, temporary.st_ino) != (expected.st_dev, expected.st_ino):
        raise RuntimeError("temporary output pathname was replaced")
    os.link(
        temporary_name, output.name,
        src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    try:
        published = os.stat(
            output.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        reported = os.stat(output, follow_symlinks=False)
        verify_output_parent(parent_descriptor, output)
        expected_identity = (expected.st_dev, expected.st_ino)
        if ((published.st_dev, published.st_ino) != expected_identity
                or (reported.st_dev, reported.st_ino) != expected_identity):
            raise RuntimeError("published output does not match the written inode")
    except BaseException:
        os.unlink(output.name, dir_fd=parent_descriptor)
        raise


def main() -> int:
    parser = SafeArgumentParser(prog="dex-swap-repack.py", description=__doc__)
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
    parser.add_argument("--max-archive-bytes", type=int, default=MAX_ARCHIVE_BYTES)
    parser.add_argument("--max-central-directory-bytes", type=int,
                        default=MAX_CENTRAL_DIRECTORY_BYTES)
    args = parser.parse_args()

    if not DEX_ENTRY.fullmatch(args.dex_entry):
        parser.error("--dex-entry must be classes.dex or classesN.dex with N >= 2")
    for option in ("max_entries", "max_member_bytes", "max_aggregate_bytes",
                   "max_compression_ratio", "max_archive_bytes",
                   "max_central_directory_bytes"):
        if getattr(args, option) <= 0:
            parser.error(f"--{option.replace('_', '-')} must be positive")

    apk_source = args.apk.expanduser().absolute()
    replacement_source = args.replacement_dex.expanduser().absolute()
    parent_descriptor = -1
    try:
        output, parent_descriptor = resolve_new_output(args.output)
        with tempfile.TemporaryDirectory(prefix="dex-swap-inputs-") as snapshot_directory:
            snapshots = Path(snapshot_directory)
            apk = snapshots / "input.apk"
            replacement = snapshots / "replacement.dex"
            apk_hash, apk_size = snapshot_input(
                apk_source, apk, args.max_archive_bytes
            )
            replacement_hash, _ = snapshot_input(
                replacement_source, replacement, args.max_member_bytes
            )
            preflight_zip(apk, args.max_entries, args.max_central_directory_bytes)
            dex_facts = validate_dex(replacement)
            temporary_name = ""
            try:
                temporary_name, descriptor = create_temporary(parent_descriptor)
                with os.fdopen(descriptor, "w+b") as temporary:
                    facts = repack(
                        apk, replacement, args.dex_entry, temporary,
                        args.max_entries, args.max_member_bytes,
                        args.max_aggregate_bytes, args.max_compression_ratio,
                    )
                    temporary.flush()
                    os.fsync(temporary.fileno())
                    output_hash, output_size = digest_stream(temporary)
                    publish_temporary(
                        parent_descriptor, temporary_name, output,
                        temporary.fileno(),
                    )
            finally:
                if temporary_name:
                    try:
                        os.unlink(temporary_name, dir_fd=parent_descriptor)
                    except FileNotFoundError:
                        pass
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError,
            struct.error) as error:
        raise SystemExit(f"ERR: {safe_message(error)}") from error
    finally:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)

    report = {
        "authorization_ref": args.authorization_ref,
        "input": {"path": str(apk_source), "sha256": apk_hash, "bytes": apk_size},
        "replacement": {"path": str(replacement_source), "sha256": replacement_hash,
                        **dex_facts},
        "output": {"path": str(output), "sha256": output_hash, "bytes": output_size,
                   "signing": "required"},
        **facts,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
