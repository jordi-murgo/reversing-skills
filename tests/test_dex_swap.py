from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "apk-reversing-playbook" / "scripts" / "dex-swap-repack.py"


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


if __name__ == "__main__":
    unittest.main()
