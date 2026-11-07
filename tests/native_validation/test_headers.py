"""Frozen builder boundary controls for QA F1; invented fixed headers only."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path.cwd()/'scripts'))
from native_validation import common as C


class FixedHeaders(unittest.TestCase):
    def check(self, target, length):
        body = bytearray(length)
        if target.endswith('linux-gnu'):
            body[:6] = b'\x7fELF\x02\x01'
            body[18:20] = struct.pack('<H', 62)
        else:
            body[:4] = b'\xcf\xfa\xed\xfe'
            body[4:8] = struct.pack('<I', 0x1000007)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'invented-header'
            path.write_bytes(body)
            return C.binary_arch(path, target)

    def test_full_elf_control(self):
        self.assertIsNone(self.check('x86_64-unknown-linux-gnu', 64))

    def test_short_elf_discriminator_is_not_full_header(self):
        with self.assertRaises(ValueError):
            self.check('x86_64-unknown-linux-gnu', 20)

    def test_full_macho_control(self):
        self.assertIsNone(self.check('x86_64-apple-darwin', 32))

    def test_short_macho_discriminator_is_not_full_header(self):
        with self.assertRaises(ValueError):
            self.check('x86_64-apple-darwin', 8)


if __name__ == '__main__':
    unittest.main(verbosity=2)
