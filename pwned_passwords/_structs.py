from typing import Literal, NamedTuple


__all__ = ["PwnedHash", "PwnedOptions", "PwnedResults"]


class PwnedHash(NamedTuple):
    """Returned a hash from a Pwned Passwords API check."""

    suffix: str
    count: int


class PwnedOptions(NamedTuple):
    """Pwned Passwords API options."""

    add_padding: bool = False
    mode: Literal["sha1", "ntlm"] = "sha1"

    # Library-specific option
    get_hashes: bool = False


class PwnedResults(NamedTuple):
    """Report the Pwned Passwords results."""

    is_pwned: bool
    times_pwned: int
    hashes: list[PwnedHash]
