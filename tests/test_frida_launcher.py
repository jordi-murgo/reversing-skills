from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "android-frida-runtime" / "scripts" / "frida-run.sh"


def executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class FridaLauncherTests(unittest.TestCase):
    def run_launcher(self, version: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        binary = root / "bin"
        binary.mkdir()
        executable(binary / "frida", "#!/bin/sh\n[ \"$1\" = --version ] && { echo 17.23.1; exit 0; }\nprintf '%s\\n' \"$*\"\n")
        executable(binary / "frida-ps", "#!/bin/sh\nexit 0\n")
        hook = root / "hook.js"
        hook.write_text("console.log('fixture');\n", encoding="utf-8")
        environment = os.environ.copy()
        environment["PATH"] = f"{binary}:{environment['PATH']}"
        return subprocess.run(
            [shutil.which("bash") or "bash", str(SCRIPT), "--package", "com.example.app",
             "--script", str(hook), "--expected-version", version, *arguments],
            text=True, capture_output=True, check=False, env=environment,
        )

    def test_spawn_is_default_without_removed_no_pause_flag(self) -> None:
        result = self.run_launcher("17.23.1", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mode=spawn", result.stdout)
        self.assertIn(" -f com.example.app ", result.stdout)
        self.assertNotIn("--no-pause", result.stdout)
        self.assertNotIn(" -n com.example.app ", result.stdout)

    def test_version_mismatch_stops_before_spawn(self) -> None:
        result = self.run_launcher("17.23.2", "--dry-run")
        self.assertEqual(result.returncode, 1)
        self.assertIn("!= expected server", result.stderr)


if __name__ == "__main__":
    unittest.main()
