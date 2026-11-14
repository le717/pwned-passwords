import unittest
from pathlib import Path
from unittest.mock import create_autospec

import pwned_passwords
from pwned_passwords import _utils


class TestCheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sha1_no_padding = (
            Path("tests") / "test-data" / "password-sha1-no-padding.txt"
        ).read_text()
        cls.original_make_request = _utils.make_request
        _utils.make_request = create_autospec(_utils.make_request, return_value=cls.sha1_no_padding)

    @classmethod
    def tearDownClass(cls) -> None:
        _utils.make_request = cls.original_make_request  # type: ignore[reportAttributeAccessIssue, ty:invalid-assignment]

    def test_check_with_string_default_options(self) -> None:
        result = pwned_passwords.check("password")
        self.assertTrue(result.is_pwned)

    def test_check_with_bytes_default_options(self) -> None:
        result = pwned_passwords.check(b"password")
        self.assertTrue(result.is_pwned)
        pwned_passwords.check(b"password")

    def test_check_with_hashes_in_results(self) -> None:
        result = pwned_passwords.check(
            "password", options=pwned_passwords.PwnedOptions(get_hashes=True)
        )
        self.assertTrue(result.is_pwned)
        pwned_passwords.check(b"password")
        self.assertTrue(
            all(True for h in result.hashes if h.suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
        )

    def test_check_with_options_not_named_argument(self) -> None:
        with self.assertRaises(TypeError):
            pwned_passwords.check("password", pwned_passwords.PwnedOptions(get_hashes=True))  # type: ignore[reportCallIssue, ty:too-many-positional-arguments]
