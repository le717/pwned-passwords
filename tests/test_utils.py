import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import create_autospec

from pwned_passwords import _md4, _structs, _utils, exceptions


class TestUtilsAPIOptions(unittest.TestCase):
    def test_padding_disabled(self) -> None:
        opts = _structs.PwnedOptions(add_padding=False)
        headers, _ = _utils.build_request_options(opts)
        self.assertDictEqual(headers, {})

    def test_padding_enabled(self) -> None:
        opts = _structs.PwnedOptions(add_padding=True)
        headers, _ = _utils.build_request_options(opts)
        self.assertDictEqual(headers, {"Add-Padding": "true"})

    def test_mode_not_specified(self) -> None:
        opts = _structs.PwnedOptions()
        _, params = _utils.build_request_options(opts)
        self.assertDictEqual(params, {})

    def test_mode_ntlm(self) -> None:
        opts = _structs.PwnedOptions(mode="ntlm")
        _, params = _utils.build_request_options(opts)
        self.assertDictEqual(params, {"mode": "ntlm"})

    def test_mode_something_else(self) -> None:
        opts = _structs.PwnedOptions(mode="unsupported_hash")  # type: ignore[reportArgumentType, ty:invalid-argument-type]
        _, params = _utils.build_request_options(opts)
        self.assertDictEqual(params, {})

    def test_default_options(self) -> None:
        opts = _structs.PwnedOptions()
        headers, params = _utils.build_request_options(opts)
        self.assertDictEqual(headers, {})
        self.assertDictEqual(params, {})

    def test_options_is_none_is_error(self) -> None:
        with self.assertRaises(TypeError):
            _utils.build_request_options()  # type: ignore[reportCallIssue, ty:missing-argument]


class TestUtilsAlgo(unittest.TestCase):
    def test_unknown_algo(self) -> None:
        with self.assertRaises(exceptions.UnsupportedAlgoError) as exc:
            _utils.generate_hash("unsupported_hash", "password")
        self.assertIn(
            "Unsupported hashing algorithm: 'unsupported_hash'. Available options: 'sha1'",
            str(exc.exception),
        )


class TestUtilsMakeRequest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sha1_no_padding = (
            Path("tests") / "test-data" / "password-sha1-no-padding.txt"
        ).read_text()
        cls.ntlm_no_padding = (
            Path("tests") / "test-data" / "password-ntlm-no-padding.txt"
        ).read_text()

    def test_password_sha1_hash_in_response(self) -> None:
        make_request = create_autospec(_utils.make_request, return_value=self.sha1_no_padding)
        hash = _utils.generate_hash("sha1", "password")[:5]
        result = make_request(hash, {}, {})
        self.assertIn("1E4C9B93F3F0682250B6CF8331B7EE68FD8", result)

    def test_password_sha1_hash_in_response_dont_provide_first_five(self) -> None:
        make_request = create_autospec(_utils.make_request, return_value=self.sha1_no_padding)
        hash = _utils.generate_hash("sha1", "password")
        result = make_request(hash, {}, {})
        self.assertIn("1E4C9B93F3F0682250B6CF8331B7EE68FD8", result)

    @unittest.skipIf(not _md4.has_md4, "no md4 support")
    def test_password_ntlm_hash_in_response(self) -> None:
        make_request = create_autospec(_utils.make_request, return_value=self.ntlm_no_padding)
        hash = _utils.generate_hash("ntlm", "password")[:5]
        result = make_request(hash, {}, {})
        self.assertIn("7EAEE8FB117AD06BDD830B7586C", result)


class TestUtilsParseResponse(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sha1_no_padding = (
            Path("tests") / "test-data" / "password-sha1-no-padding.txt"
        ).read_text()
        cls.sha1_padding = (Path("tests") / "test-data" / "password-sha1-padding.txt").read_text()
        cls.ntlm_no_padding = (
            Path("tests") / "test-data" / "password-ntlm-no-padding.txt"
        ).read_text()
        cls.ntlm_padding = (Path("tests") / "test-data" / "password-ntlm-padding.txt").read_text()

    def test_pwned_password_sha1_no_hashes(self) -> None:
        hash = _utils.generate_hash("sha1", "password")
        r = _utils.parse_response(hash, self.sha1_no_padding, get_hashes=False)
        self.assertTrue(r.is_pwned)
        self.assertEqual(r.times_pwned, 9659365)
        self.assertListEqual(r.hashes, [])

    def test_pwned_password_sha1_with_hashes(self) -> None:
        hash = _utils.generate_hash("sha1", "password")
        r = _utils.parse_response(hash, self.sha1_no_padding, get_hashes=True)
        self.assertTrue(r.is_pwned)
        self.assertEqual(r.times_pwned, 9659365)
        self.assertEqual(len(r.hashes), 816)

    def test_pwned_password_sha1_no_zero_results(self) -> None:
        hash = _utils.generate_hash("sha1", "password")
        r = _utils.parse_response(hash, self.sha1_padding, get_hashes=True)
        self.assertTrue(r.is_pwned)
        self.assertEqual(r.times_pwned, 9659365)
        self.assertEqual(len(r.hashes), 816)
        self.assertNotIn(0, Counter(result.count for result in r.hashes))

    def test_unpwned_password_sha1_no_results(self) -> None:
        hash = _utils.generate_hash("sha1", "this_password_is_not_in_the_result_set")
        r = _utils.parse_response(hash, self.sha1_no_padding, get_hashes=False)
        self.assertFalse(r.is_pwned)
        self.assertEqual(r.times_pwned, 0)
        self.assertListEqual(r.hashes, [])

    @unittest.skipIf(not _md4.has_md4, "no md4 support")
    def test_pwned_password_ntlm_no_hashes(self) -> None:
        hash = _utils.generate_hash("ntlm", "password")
        r = _utils.parse_response(hash, self.ntlm_no_padding, get_hashes=False)
        self.assertTrue(r.is_pwned)
        self.assertEqual(r.times_pwned, 9659365)
        self.assertListEqual(r.hashes, [])

    @unittest.skipIf(not _md4.has_md4, "no md4 support")
    def test_pwned_password_ntlm_with_hashes(self) -> None:
        hash = _utils.generate_hash("ntlm", "password")
        r = _utils.parse_response(hash, self.ntlm_no_padding, get_hashes=True)
        self.assertTrue(r.is_pwned)
        self.assertEqual(r.times_pwned, 9659365)
        self.assertEqual(len(r.hashes), 859)

    @unittest.skipIf(not _md4.has_md4, "no md4 support")
    def test_pwned_password_ntlm_no_zero_results(self) -> None:
        hash = _utils.generate_hash("ntlm", "password")
        r = _utils.parse_response(hash, self.ntlm_padding, get_hashes=True)
        self.assertTrue(r.is_pwned)
        self.assertEqual(r.times_pwned, 9659365)
        self.assertEqual(len(r.hashes), 859)
        self.assertNotIn(0, Counter(result.count for result in r.hashes))

    @unittest.skipIf(not _md4.has_md4, "no md4 support")
    def test_unpwned_password_ntlm_no_results(self) -> None:
        hash = _utils.generate_hash("ntlm", "this_password_is_not_in_the_result_set")
        r = _utils.parse_response(hash, self.ntlm_no_padding, get_hashes=False)
        self.assertFalse(r.is_pwned)
        self.assertEqual(r.times_pwned, 0)
        self.assertListEqual(r.hashes, [])
