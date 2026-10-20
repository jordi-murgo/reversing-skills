from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "android-packed-native" / "scripts" / "triage-native-libs.py"


def load_module():
    spec = importlib.util.spec_from_file_location("packed_native", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_elf(entry: int) -> bytes:
    data = bytearray(bytes(range(256)) * 32)
    data[0:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    struct.pack_into("<H", data, 18, 183)
    struct.pack_into("<Q", data, 24, entry)
    return bytes(data)


class PackedNativeTests(unittest.TestCase):
    def test_zero_entry_is_weak_and_does_not_change_score(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            zero = module.inspect_library(synthetic_elf(0), "zero.so", root)
            nonzero = module.inspect_library(synthetic_elf(0x1000), "nonzero.so", root)
        self.assertTrue(any("entry is zero" in reason for reason in zero["weak_signals"]))
        self.assertEqual(nonzero["weak_signals"], [])
        self.assertEqual(zero["candidate_score"], nonzero["candidate_score"])
        self.assertIn("very few plausible ARM64 frame prologues", zero["candidate_reasons"])

    def test_entropy_bounds(self) -> None:
        module = load_module()
        self.assertEqual(module.entropy(b"\x00" * 4096), 0.0)
        self.assertAlmostEqual(module.entropy(bytes(range(256)) * 16), 8.0)


if __name__ == "__main__":
    unittest.main()
