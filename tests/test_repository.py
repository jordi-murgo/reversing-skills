from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILLS = (
    "apk-reversing-playbook",
    "android-apk-intake",
    "android-packed-native",
    "android-structural-diff",
    "android-keystore-analysis",
    "android-frida-runtime",
    "arxan-guardit-android",
)
SECTIONS = (
    "## Activation Contract",
    "## Hard Rules",
    "## Decision Gates",
    "## Execution Steps",
    "## Output Contract",
    "## References",
)


def parse_frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise ValueError("missing YAML frontmatter")
    block = text.split("\n---\n", 1)[0][4:]
    result: dict[str, str] = {}
    for line in block.splitlines():
        match = re.match(r"^([a-z][a-z0-9_-]*):\s*(.*)$", line)
        if match:
            result[match.group(1)] = match.group(2).strip().strip('"')
    return result


def validate_skill(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
        metadata = parse_frontmatter(text)
    except (OSError, ValueError) as error:
        return [str(error)]
    for key in ("name", "description", "license", "metadata"):
        if key not in metadata:
            errors.append(f"missing frontmatter key: {key}")
    if metadata.get("name") != path.parent.name:
        errors.append("name does not match directory")
    description = metadata.get("description", "")
    if not description or len(description) > 250 or "\n" in description:
        errors.append("description must be one line and at most 250 characters")
    positions = [text.find(section) for section in SECTIONS]
    if any(position < 0 for position in positions):
        errors.append("missing required section")
    elif positions != sorted(positions):
        errors.append("required sections are out of order")
    for reference in re.findall(r"`((?:scripts|references|assets)/[^`\s]+)`", text):
        if not (path.parent / reference).is_file():
            errors.append(f"missing local reference: {reference}")
    return errors


class RepositoryContractTests(unittest.TestCase):
    def test_skills_follow_contract(self) -> None:
        for name in SKILLS:
            with self.subTest(skill=name):
                skill = ROOT / name / "SKILL.md"
                self.assertTrue(skill.is_file())
                self.assertEqual(validate_skill(skill), [])

    def test_gate_rejects_negative_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "wrong-name"
            directory.mkdir()
            skill = directory / "SKILL.md"
            skill.write_text("---\nname: other\n---\n# Broken\n", encoding="utf-8")
            self.assertTrue(validate_skill(skill))

    def test_referenced_scripts_are_executable_and_parse(self) -> None:
        scripts = sorted(
            [
                path
                for name in SKILLS
                for path in (ROOT / name / "scripts").glob("*")
                if path.is_file()
            ]
            + [path for path in (ROOT / "scripts").glob("*") if path.is_file()]
        )
        self.assertTrue(scripts)
        for script in scripts:
            with self.subTest(script=script.relative_to(ROOT)):
                if script.suffix == ".py":
                    try:
                        compile(script.read_text(encoding="utf-8"), str(script), "exec")
                    except SyntaxError as error:
                        self.fail(str(error))
                    continue
                result = subprocess.run(
                    ["bash", "-n", str(script)], capture_output=True,
                    text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_repository_contains_no_target_artifacts_or_client_markers(self) -> None:
        forbidden_suffixes = {".apk", ".apks", ".xapk", ".apkm", ".aab", ".dex", ".so"}
        files = [path for path in ROOT.rglob("*") if path.is_file() and ".git" not in path.parts]
        self.assertFalse([path for path in files if path.suffix.lower() in forbidden_suffixes])
        forbidden = ("bs-" + "mobile", "Banc " + "Sabadell", "192." + "168.1.", "/home/" + "jordi")
        for path in files:
            if path.suffix in {".md", ".py", ".sh", ".json", ".csv", ".example"}:
                text = path.read_text(encoding="utf-8", errors="replace")
                for marker in forbidden:
                    self.assertNotIn(marker, text, f"{marker!r} found in {path}")


if __name__ == "__main__":
    unittest.main()
