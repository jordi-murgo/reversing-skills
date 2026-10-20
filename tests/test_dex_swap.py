from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "apk-reversing-playbook" / "scripts" / "dex-swap-repack.py"

def load_module():
    spec = importlib.util.spec_from_file_location("dex_swap", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_dex(path: Path, payload: bytes) -> None:
    data = bytearray(0x70 + len(payload))
    data[:8] = b"dex\n035\x00"
    struct.pack_into("<III", data, 0x20, len(data), 0x70, 0x12345678)
    data[0x70:] = payload
    path.write_bytes(data)


def write_apk(path: Path, dex: bytes, unsafe: bool = False) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        manifest = zipfile.ZipInfo("AndroidManifest.xml")
        manifest.compress_type = zipfile.ZIP_DEFLATED
        manifest.external_attr = 0o644 << 16
        archive.writestr(manifest, b"manifest-fixture")
        target = zipfile.ZipInfo("classes2.dex")
        target.compress_type = zipfile.ZIP_STORED
        target.external_attr = 0o644 << 16
        archive.writestr(target, dex)
        archive.writestr("../escape", b"unsafe") if unsafe else None
        archive.comment = b"fixture-comment"


class DexSwapTests(unittest.TestCase):
    def test_cli_replaces_only_selected_dex_and_preserves_container_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_dex = root / "original.dex"
            replacement = root / "replacement.dex"
            write_dex(original_dex, b"original")
            write_dex(replacement, b"patched")
            apk = root / "input.apk"
            output = root / "output.apk"
            write_apk(apk, original_dex.read_bytes())
            input_hash = digest(apk)

            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(apk), str(replacement),
                 "--dex-entry", "classes2.dex", "--output", str(output),
                 "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["authorization_ref"], "ROE-test")
            self.assertEqual(report["output"]["signing"], "required")
            self.assertEqual(digest(apk), input_hash)
            with zipfile.ZipFile(apk) as source, zipfile.ZipFile(output) as rebuilt:
                self.assertEqual(rebuilt.namelist(), source.namelist())
                self.assertEqual(rebuilt.comment, source.comment)
                self.assertEqual(rebuilt.read("AndroidManifest.xml"),
                                 source.read("AndroidManifest.xml"))
                self.assertEqual(rebuilt.read("classes2.dex"), replacement.read_bytes())
                self.assertEqual(rebuilt.getinfo("classes2.dex").compress_type,
                                 source.getinfo("classes2.dex").compress_type)
                self.assertEqual(rebuilt.getinfo("AndroidManifest.xml").external_attr,
                                 source.getinfo("AndroidManifest.xml").external_attr)

    def test_input_snapshot_binds_hash_to_copied_bytes(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.apk"
            snapshot = root / "snapshot.apk"
            original = b"original-input"
            source.write_bytes(original)
            value, size = module.snapshot_input(source, snapshot, 1024)
            source.write_bytes(b"substituted")
            self.assertEqual(snapshot.read_bytes(), original)
            self.assertEqual(value, hashlib.sha256(original).hexdigest())
            self.assertEqual(size, len(original))

    def test_temporary_publication_rejects_replaced_pathname(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            victim = root / "victim"
            victim.write_bytes(b"preserve")
            parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            temporary_name = ""
            descriptor = -1
            try:
                temporary_name, descriptor = module.create_temporary(parent)
                os.write(descriptor, b"safe-output")
                os.unlink(temporary_name, dir_fd=parent)
                (root / temporary_name).symlink_to(victim)
                with self.assertRaisesRegex(RuntimeError, "pathname was replaced"):
                    module.publish_temporary(
                        parent, temporary_name, root / "output.apk", descriptor
                    )
                self.assertEqual(victim.read_bytes(), b"preserve")
                self.assertFalse((root / "output.apk").exists())
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                if temporary_name:
                    (root / temporary_name).unlink(missing_ok=True)
                os.close(parent)

    def test_output_parent_descriptor_rejects_path_replacement(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            moved = root / "moved"
            parent.mkdir()
            output, parent_descriptor = module.resolve_new_output(
                parent / "output.apk"
            )
            temporary_name = ""
            descriptor = -1
            try:
                parent.rename(moved)
                parent.mkdir()
                temporary_name, descriptor = module.create_temporary(
                    parent_descriptor
                )
                os.write(descriptor, b"pinned-output")
                with self.assertRaisesRegex(RuntimeError, "parent pathname was replaced"):
                    module.publish_temporary(
                        parent_descriptor, temporary_name, output, descriptor
                    )
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                if temporary_name:
                    try:
                        os.unlink(temporary_name, dir_fd=parent_descriptor)
                    except FileNotFoundError:
                        pass
                os.close(parent_descriptor)
            self.assertFalse((parent / "output.apk").exists())
            self.assertFalse((moved / "output.apk").exists())

    def test_preflight_reconciles_metadata_and_fifo_fails_promptly(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replacement = root / "replacement.dex"
            original = root / "original.dex"
            write_dex(replacement, b"patched")
            write_dex(original, b"original")
            safe = root / "safe.apk"
            write_apk(safe, original.read_bytes())
            source = bytearray(safe.read_bytes())
            eocd = source.rfind(module.EOCD_SIGNATURE)
            self.assertGreaterEqual(eocd, 0)

            forged = root / "forged-count.apk"
            forged_data = bytearray(source)
            struct.pack_into("<HH", forged_data, eocd + 8, 1, 1)
            forged.write_bytes(forged_data)
            forged_result = subprocess.run(
                [sys.executable, str(SCRIPT), str(forged), str(replacement),
                 "--dex-entry", "classes2.dex", "--output",
                 str(root / "forged-output.apk"), "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(forged_result.returncode, 0)
            self.assertIn("entry count disagrees", forged_result.stderr)

            fields = module.EOCD.unpack_from(source, eocd)
            zip64_record = module.ZIP64_EOCD.pack(
                module.ZIP64_EOCD_SIGNATURE, 44, 45, 45, 0, 0,
                fields[4], fields[4], fields[5], fields[6],
            )
            locator = module.ZIP64_LOCATOR.pack(
                module.ZIP64_LOCATOR_SIGNATURE, 0, eocd, 1
            )
            noncanonical = root / "noncanonical-zip64.apk"
            noncanonical.write_bytes(
                source[:eocd] + zip64_record + locator + source[eocd:]
            )
            zip64_result = subprocess.run(
                [sys.executable, str(SCRIPT), str(noncanonical), str(replacement),
                 "--dex-entry", "classes2.dex", "--output",
                 str(root / "zip64-output.apk"), "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(zip64_result.returncode, 0)
            self.assertIn("noncanonical ZIP64", zip64_result.stderr)

            fake_comment = root / "fake-comment.apk"
            write_apk(fake_comment, original.read_bytes())
            with zipfile.ZipFile(fake_comment, "a") as archive:
                archive.comment = b"prefix" + module.EOCD_SIGNATURE + b"junk"
            fake_comment_result = subprocess.run(
                [sys.executable, str(SCRIPT), str(fake_comment), str(replacement),
                 "--dex-entry", "classes2.dex", "--output",
                 str(root / "fake-comment-output.apk"),
                 "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(fake_comment_result.returncode, 0)
            self.assertIn("ZIP end record", fake_comment_result.stderr)

            fifo = root / "input.fifo"
            os.mkfifo(fifo)
            fifo_result = subprocess.run(
                [sys.executable, str(SCRIPT), str(fifo), str(replacement),
                 "--dex-entry", "classes2.dex", "--output",
                 str(root / "fifo-output.apk"), "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False, timeout=2,
            )
            self.assertNotEqual(fifo_result.returncode, 0)
            self.assertIn("not a regular file", fifo_result.stderr)

    def test_negative_fixtures_reject_unsafe_apk_and_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replacement = root / "replacement.dex"
            write_dex(replacement, b"patched")
            original = root / "original.dex"
            write_dex(original, b"original")
            unsafe = root / "unsafe.apk"
            write_apk(unsafe, original.read_bytes(), unsafe=True)
            output = root / "output.apk"

            rejected = subprocess.run(
                [sys.executable, str(SCRIPT), str(unsafe), str(replacement),
                 "--dex-entry", "classes2.dex", "--output", str(output),
                 "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("unsafe member", rejected.stderr)
            self.assertFalse(output.exists())

            control_name = "evil\n\x1b]52;c;payload\x07"
            control_apk = root / "control.apk"
            with zipfile.ZipFile(control_apk, "w") as archive:
                archive.writestr("classes2.dex", original.read_bytes())
                archive.writestr(control_name, b"unsafe")
            control_output = root / "control-output.apk"
            control = subprocess.run(
                [sys.executable, str(SCRIPT), str(control_apk), str(replacement),
                 "--dex-entry", "classes2.dex", "--output", str(control_output),
                 "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(control.returncode, 0)
            self.assertNotIn("\x1b", control.stderr)
            self.assertIn("\\n", control.stderr)
            self.assertIn("\\x1b", control.stderr)
            self.assertFalse(control_output.exists())

            safe = root / "safe.apk"
            write_apk(safe, original.read_bytes())
            budget_output = root / "budget-output.apk"
            budget = subprocess.run(
                [sys.executable, str(SCRIPT), str(safe), str(replacement),
                 "--dex-entry", "classes2.dex", "--output", str(budget_output),
                 "--authorization-ref", "ROE-test", "--max-entries", "1"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(budget.returncode, 0)
            self.assertIn("exceeds 1 entries", budget.stderr)
            self.assertFalse(budget_output.exists())
            dangling_target = root / "outside.apk"
            dangling_output = root / "dangling.apk"
            dangling_output.symlink_to(dangling_target)
            dangling = subprocess.run(
                [sys.executable, str(SCRIPT), str(safe), str(replacement),
                 "--dex-entry", "classes2.dex", "--output", str(dangling_output),
                 "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(dangling.returncode, 0)
            self.assertIn("output already exists", dangling.stderr)
            self.assertTrue(dangling_output.is_symlink())
            self.assertFalse(dangling_target.exists())
            output.write_bytes(b"do-not-overwrite")
            existing = subprocess.run(
                [sys.executable, str(SCRIPT), str(safe), str(replacement),
                 "--dex-entry", "classes2.dex", "--output", str(output),
                 "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(existing.returncode, 0)
            self.assertIn("output already exists", existing.stderr)
            self.assertEqual(output.read_bytes(), b"do-not-overwrite")

            unsafe_path = root / "missing\n\x1b]52;c;payload\x07.apk"
            escaped = subprocess.run(
                [sys.executable, str(SCRIPT), str(unsafe_path), str(replacement),
                 "--dex-entry", "classes2.dex", "--output",
                 str(root / "escaped.apk"), "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(escaped.returncode, 0)
            self.assertNotIn("\x1b", escaped.stderr)
            self.assertNotIn("\x07", escaped.stderr)
            self.assertIn("\\x1b", escaped.stderr)

            parser_control = "extra\x1b]52;c;payload\x07"
            parser_error = subprocess.run(
                [sys.executable, str(SCRIPT), str(safe), str(replacement),
                 "--dex-entry", "classes2.dex", "--output",
                 str(root / "parser.apk"), "--authorization-ref", "ROE-test",
                 parser_control],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(parser_error.returncode, 0)
            self.assertNotIn("\x1b", parser_error.stderr)
            self.assertNotIn("\x07", parser_error.stderr)
            self.assertIn("\\x1b", parser_error.stderr)


if __name__ == "__main__":
    unittest.main()
