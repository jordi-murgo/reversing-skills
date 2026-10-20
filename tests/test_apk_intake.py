from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "android-apk-intake" / "scripts" / "intake-apk-set.py"


def load_module():
    spec = importlib.util.spec_from_file_location("apk_intake", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_apk(path: Path, dex: str, abi: str | None = None) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(dex, b"dex\n035\x00fixture")
        archive.writestr("AndroidManifest.xml", b"fixture")
        if abi:
            archive.writestr(f"lib/{abi}/libfixture.so", b"\x7fELFfixture")


class ApkIntakeTests(unittest.TestCase):
    def test_archive_traversal_is_rejected(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "bad.apks"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("../escape.apk", b"not-safe")
            with self.assertRaisesRegex(ValueError, "unsafe archive member"):
                module.extract_archive(source, root / "output")

    def test_split_set_manifest_preserves_inventory_and_uncertainty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base.apk"
            split = root / "config.arm64_v8a.apk"
            make_apk(base, "classes.dex", "arm64-v8a")
            make_apk(split, "classes2.dex")
            source = root / "set.apks"
            with zipfile.ZipFile(source, "w") as archive:
                archive.write(base, "base.apk")
                archive.write(split, "splits/config.arm64_v8a.apk")
            output = root / "evidence"
            empty_path = root / "empty-bin"
            empty_path.mkdir()
            environment = os.environ.copy()
            environment["PATH"] = str(empty_path)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(source), "--output", str(output),
                 "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False, env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["authorization_ref"], "ROE-test")
            self.assertEqual(manifest["summary"]["apk_count"], 2)
            self.assertIsNone(manifest["summary"]["signer_consistent"])
            self.assertEqual(manifest["summary"]["set_consistency"], "unknown")
            records = manifest["artifacts"]
            self.assertEqual({record["archive"]["status"] for record in records}, {"valid"})
            self.assertIn("arm64-v8a", records[0]["archive"]["abis"])
            self.assertEqual(len({record["sha256"] for record in records}), 2)
            schema = json.loads((ROOT / "android-apk-intake" / "assets" /
                                 "evidence-manifest.schema.json").read_text())
            self.assertTrue(set(schema["required"]).issubset(manifest))


if __name__ == "__main__":
    unittest.main()
