import hashlib
from typing import NoReturn

from .exceptions import UnsupportedAlgoError


__all__ = ["has_md4", "md4"]


def _no_md4_support(data: bytes, /) -> NoReturn:
    """Raise an exception when trying to use NTLM hashing without md4 hash support."""
    raise UnsupportedAlgoError("Unsupported hashing algorithm: 'ntlm'. Available options: 'sha1'.")


def _fallback_md4(data: bytes, /) -> str:
    """Generate an md4 hash using pyspengo."""
    return pyspnego_md4(data).hex().upper()


def _first_class_md4(data: bytes, /) -> str:
    """Generate an md4 hash using hashlib."""
    return hashlib.new("md4", data).hexdigest().upper()


# Try to use the implementation available in hashlib if present
if "md4" in hashlib.algorithms_available:
    has_md4 = True
    md4 = _first_class_md4
else:
    # If it is not in hashlib, fallback to pyspengo
    try:
        from spnego._ntlm_raw.md4 import md4 as pyspnego_md4  # type: ignore[reportMissingImports, ty:import-not-found]

        has_md4 = True

        md4 = _fallback_md4

    # But if that is not installed, we can only throw an error
    except ModuleNotFoundError:
        has_md4 = False
        md4 = _no_md4_support
