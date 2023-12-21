import hashlib
from typing import NoReturn

import httpx
from spnego._ntlm_raw.md4 import md4

from ._structs import PwnedHash, PwnedOptions, PwnedResults


__all__ = ["build_request_options", "generate_hash", "make_request", "parse_response"]


def _fallback_md4(value: bytes) -> str:
    """Generate an md4 hash using pyspengo."""
    # TIL about the existence of `bytes.hex() -> str`
    return md4(value).hex().upper()


def build_request_options(options: PwnedOptions, /) -> tuple[dict[str, str], dict[str, str]]:
    """Build out the required config structures for making an API call."""
    headers = {}
    params = {}

    # Enable response padding
    if options.add_padding:
        headers["Add-Padding"] = "true"

    # Return NTLM hashes instead of the SHA-1 default.
    # NTLM is the only other supported option. If anything other than
    # "ntlm" is provided, we want SHA-1, and there's no way to get
    # SHA-1 hashes than to not provide the mode parameter, at least properly,
    # according to the API docs
    if options.mode == "ntlm":
        params["mode"] = "ntlm"

    return (headers, params)


def generate_hash(hash_type: str, password: str, /) -> str | NoReturn:
    """Generate a hash of the specified type for the given value."""
    # Generate an SHA-1 hash
    if hash_type == "sha1":
        if isinstance(password, str):
            password = password.encode()
        return hashlib.sha1(password).hexdigest().upper()

    # Generate an NTLM hash
    # https://stackoverflow.com/questions/15603628/how-to-calculate-ntlm-hash-in-python#comment56664902_15603809  # noqa
    if hash_type == "ntlm":
        # If we got bytes, convert it back to a string before making it a specific type of bytes
        if isinstance(password, bytes):
            password = password.decode()
        password = password.encode("utf-16le")

        # If the MD4 algo is not available via hashlib, we need to fallback to pyspnego
        if "md4" not in hashlib.algorithms_available:
            return _fallback_md4(password)
        return hashlib.new("md4", password).hexdigest().upper()

    # We don't support that algo
    raise NotImplementedError(
        f"Unsupported hashing algorithm: {hash_type!r}. Available options: 'sha1', 'ntlm'"
    )


def make_request(hash_first_five: str, /, headers: dict[str, str], params: dict[str, str]) -> str:
    """Actually make a request to the Pwned Passwords API."""
    API_URL: str = "https://api.pwnedpasswords.com/range/{hash}"

    r = httpx.get(
        API_URL.format(hash=hash_first_five[:5]),
        headers=headers,
        params=params,
    )
    r.raise_for_status()
    return r.text


def parse_response(hash_full: str, response: str, /, get_hashes: bool = False) -> PwnedResults:
    """Parse an API response into a easy to consume structure.

    Respects the `PwnedOptions.get_hashes` flag and only provides hashes if
    the flag is set to `True`. This is done to speed up the parsing.
    """
    is_pwned = False
    times_pwned = 0
    hashes = []

    # Start by splitting the results into a list of individual hashes
    items: list[str] = response.strip().split("\n")

    for item in items:
        # We know that, from basic knowledge of plain text, newlines
        # are represented as \n, aka LF newlines. However, Windows uses CRLF newlines, \r\n.
        # In testing, it seems the API returns \r\n newlines, but I kinda consider
        # that an implementation detail and not set in stone. Additionally,
        # there are unit tests for this method, and depending on what platform
        # we are running them on, they could possibly only have LF newlines.
        # For safely, we only split the lines on \n and remove any remaining whitespace
        # for consistency. It _should_ be optional on the hash suffix, but, leave nothing to chance
        suffix, count = item.split(":")
        suffix = suffix.strip()
        count = int(count.strip())

        # From API docs about padded responses:
        # "Padded entries always have a password count of 0 and can be discarded once received."
        if count == 0:
            continue

        # Nicely structure the pwned result
        ph = PwnedHash(suffix=suffix, count=count)

        # If the caller wants the full hash list result, give it to them.
        # This could be a lot of data but, ya know, who am I to say they can't have it? *shrug*
        if get_hashes:
            hashes.append(ph)

        # If the password hash matches, it's been pwned
        if f"{hash_full[:5]}{suffix}" == hash_full:
            is_pwned = True
            times_pwned = count

            # If the caller does _not_ want the hashes, stop going through the list
            if not get_hashes:
                break

    # Provide our parsed response
    return PwnedResults(is_pwned, times_pwned, hashes)
