from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "apk-reversing-playbook" / "scripts" / "decode.sh"


class DecodeFallbackTests(unittest.TestCase):
    def test_failed_full_decode_keeps_separate_dex_trees(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            apk = root / "fixture.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", b"dex\n035\x00one")
                archive.writestr("classes2.dex", b"dex\n035\x00two")
            binary = root / "bin"
            binary.mkdir()
            jadx = binary / "jadx"
            jadx.write_text(
                "#!/bin/sh\n"
                "out=\nprev=\nlast=\n"
                "for arg in \"$@\"; do [ \"$prev\" = -d ] && out=$arg; prev=$arg; last=$arg; done\n"
                "mkdir -p \"$out/sources\"\n"
                "case \"$last\" in\n"
                "  *.apk) echo partial > \"$out/sources/Partial.java\"; exit 7 ;;\n"
                "  *) echo decoded > \"$out/sources/Decoded.java\"; exit 0 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            jadx.chmod(jadx.stat().st_mode | stat.S_IXUSR)
            environment = os.environ.copy()
            environment["PATH"] = f"{binary}:{environment['PATH']}"
            result = subprocess.run(
                [shutil.which("bash") or "bash", str(SCRIPT), str(apk),
                 "--out", str(root / "out"), "--name", "case", "--skip-apktool"],
                text=True, capture_output=True, check=False, env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            task = root / "out" / "case"
            self.assertTrue((task / "jadx-full-partial" / "sources" / "Partial.java").is_file())
            self.assertTrue((task / "jadx-dex" / "classes" / "sources" / "Decoded.java").is_file())
            self.assertTrue((task / "jadx-dex" / "classes2" / "sources" / "Decoded.java").is_file())
            self.assertFalse((task / "jadx-merged").exists())
            self.assertIn("jadx_mode=per-dex-fallback", result.stdout)


class DecodeNameSafetyTests(unittest.TestCase):
    def decode_script(self) -> Path:
        return ROOT / "apk-reversing-playbook" / "scripts" / "decode.sh"

    def test_decode_rejects_traversal_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sibling = root / "sibling"
            sibling.mkdir()
            (sibling / "valuable.txt").write_text("keep", encoding="utf-8")
            apk = root / "fixture.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", b"dex\n035\x00x")
            result = subprocess.run(
                [shutil.which("bash") or "bash", str(self.decode_script()),
                 str(apk), "--out", str(root / "out"), "--name", "../sibling",
                 "--skip-jadx", "--skip-apktool"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertTrue((sibling / "valuable.txt").is_file())
            self.assertFalse((root / "sibling").is_symlink())

    def test_decode_rejects_dotdot_derived_basename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir()
            apk = parent / "...apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", b"dex\n035\x00x")
            result = subprocess.run(
                [shutil.which("bash") or "bash", str(self.decode_script()),
                 str(apk), "--out", str(root / "out"),
                 "--skip-jadx", "--skip-apktool"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout)

    def test_decode_accepts_plain_name_and_keeps_trees_inside_out(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            apk = root / "fixture.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", b"dex\n035\x00x")
            result = subprocess.run(
                [shutil.which("bash") or "bash", str(self.decode_script()),
                 str(apk), "--out", str(root / "out"), "--name", "case",
                 "--skip-jadx", "--skip-apktool"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "out" / "case").is_dir())


if __name__ == "__main__":
    unittest.main()
