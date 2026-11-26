from typing import Literal

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

import pwned_passwords
import pwned_passwords.exceptions


__all__ = ["PwnedPasswordsValidator"]


class PwnedPasswordsValidator:
    """Django password validator that checks the given password against Pwned Passwords."""

    def __init__(
        self,
        add_padding: bool = False,
        mode: Literal["sha1", "ntlm"] = "sha1",
        get_hashes: bool = False,
        ignore_algo_error: bool = False,
    ) -> None:
        self.add_padding = add_padding
        self.mode = mode
        self.get_hashes = get_hashes
        self.ignore_algo_error = ignore_algo_error

    def validate(self, password: str, user=None) -> None:
        """Check the given password against the Pwned Passwords database."""
        try:
            result = pwned_passwords.check(
                password,
                options=pwned_passwords.PwnedOptions(
                    add_padding=self.add_padding,
                    mode=self.mode,  # type: ignore
                    get_hashes=self.get_hashes,
                ),
            )
        except pwned_passwords.exceptions.UnsupportedAlgoError:
            # If we did got an algo error, we cannot validate the password
            if not self.ignore_algo_error:
                raise ValidationError(
                    _(
                        "This password cannot be checked against the Pwned Passwords compromised "
                        "password database due to a configuration error by the app's administrator."
                    ),
                    code="password_cannot_be_checked",
                )

            # We are instructed to ignore the algo error and pretend the password is fine (ew)
            return

        if result.is_pwned:
            raise ValidationError(
                _(
                    "This password is found in the Pwned Passwords compromised password database "
                    "%(times_pwned)d times."
                ),
                code="password_is_pwned",
                params={"times_pwned": result.times_pwned},
            )

    def get_help_text(self) -> str:
        return _("Your password must not be in the Pwned Passwords compromised passwords database.")
