import unittest

from pwned_passwords import _md4, _utils


class TestUtilsNtlm(unittest.TestCase):
    @unittest.skipIf(not _md4.has_md4, "no md4 support")
    def test_ntlm_hash_with_string(self) -> None:
        """Generate an NTLM hash from a string."""
        # NTLM hash for comparison generated using https://codebeautify.org/ntlm-hash-generator
        ntlm_hash = _utils.generate_hash("ntlm", "password")
        self.assertEqual(ntlm_hash, "8846F7EAEE8FB117AD06BDD830B7586C")

    @unittest.skipIf(not _md4.has_md4, "no md4 support")
    def test_ntlm_hash_with_bytes(self) -> None:
        """Generate an NTLM hash from bytes."""
        ntlm_hash = _utils.generate_hash("ntlm", b"password")
        self.assertEqual(ntlm_hash, "8846F7EAEE8FB117AD06BDD830B7586C")

    @unittest.skipIf(_md4.has_md4, "has md4 support")
    def test_no_md4(self) -> None:
        """We do not have md4 support."""
        with self.assertRaises(NotImplementedError) as exc:
            _md4.md4("password".encode("utf-16le"))
        self.assertEqual(
            str(exc.exception), "Unsupported hashing algorithm: 'ntlm'. Available options: sha1."
        )
