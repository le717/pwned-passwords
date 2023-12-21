from . import _utils

# Re-export the structs for easier library consumption
from ._structs import PwnedHash, PwnedOptions, PwnedResults


__all__ = ["check", "check_async", "PwnedHash", "PwnedOptions", "PwnedResults"]


def check(password: bytes | str, /, options: PwnedOptions | None = None) -> PwnedResults:
    """Check a password against the Pwned Passwords API.

    https://haveibeenpwned.com/API/v3#PwnedPasswords
    """
    # If API options are not given, use the defaults
    if not isinstance(options, PwnedOptions):
        options = PwnedOptions()

    # The mode option not only changes the format the hashes are returned in,
    # but also which format we must provide. This means we technically can have
    # a mismatch in has sent vs received, but we don't want that, truly
    hash = _utils.generate_hash(options.mode, password)

    # Get the password out of memory now that we have the hash
    del password

    # Build out the API calling options
    headers, params = _utils.build_request_options(options)

    # Call out to the API and parse out the results
    response_text = _utils.make_request(hash[:5], headers=headers, params=params)
    return _utils.parse_response(hash, response_text, options.get_hashes)
