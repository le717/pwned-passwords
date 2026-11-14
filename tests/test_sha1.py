import unittest

from pwned_passwords import _utils


class TestUtilsSha1(unittest.TestCase):
    def test_sha1_hash_with_string(self) -> None:
        """Generate a SHA1 hash from a string."""
        # SHA-1 hash for comparison generated using https://github.com/veler/DevToys
        sha1_hash = _utils.generate_hash("sha1", "password")
        self.assertEqual(sha1_hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")

    def test_sha1_hash_with_bytes(self) -> None:
        """Generate a SHA1 hash from bytes."""
        sha1_hash = _utils.generate_hash("sha1", b"password")
        self.assertEqual(sha1_hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
