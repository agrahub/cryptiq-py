import secrets
from enum import StrEnum
from typing import Literal, overload

from typal.bytes import OptBytes
from typal.integers import OptInt
from typal.strings import ManyStrs, OptStr
from typal.unions import BytesOrStr


class Format(StrEnum):
    BYTES = "bytes"
    HEX = "hex"
    STRING = "string"

    @classmethod
    def choices(cls) -> ManyStrs:
        return tuple(choice.value for choice in cls)


@overload
def random(
    format: Literal[Format.BYTES],
    nbytes: OptInt = None,
    *,
    prefix: OptBytes = None,
    suffix: OptBytes = None,
) -> bytes: ...
@overload
def random(
    format: Literal[Format.HEX, Format.STRING] = Format.STRING,
    nbytes: OptInt = None,
    *,
    prefix: OptStr = None,
    suffix: OptStr = None,
) -> str: ...
def random(
    format: Format = Format.STRING,
    nbytes: OptInt = None,
    *,
    prefix: BytesOrStr | None = None,
    suffix: BytesOrStr | None = None,
) -> BytesOrStr:
    """
    Generate a cryptographically secure random token.

    This function generates secure random values using Python's
    `secrets` module and supports multiple output formats.

    The returned token type depends on the selected format:
    - `Format.BYTES` returns raw bytes
    - `Format.HEX` returns a hexadecimal string
    - `Format.STRING` returns a URL-safe string

    Optional prefixes and suffixes may be prepended or appended to
    the generated token.

    Args:
        format:
            Output token format.

        nbytes:
            Number of random bytes used to generate the token.

            Uses the underlying `secrets` module default size when
            omitted.

        prefix:
            Optional value prepended to the generated token.

        suffix:
            Optional value appended to the generated token.

    Returns:
        A cryptographically secure random token.

        - `bytes` when using `Format.BYTES`
        - `str` when using `Format.HEX` or `Format.STRING`

    Raises:
        TypeError:
            If `prefix` or `suffix` types do not match the selected
            token format.

    Notes:
        `Format.STRING` generates URL-safe tokens suitable for use in
        cookies, URLs, and temporary identifiers.

    Example:
        >>> token = random(Format.HEX, 32, prefix="api_")
    """

    if format is Format.BYTES:
        token = secrets.token_bytes(nbytes)
        if prefix is not None:
            if not isinstance(prefix, bytes):
                raise TypeError("Prefix must be a bytes")
            token = prefix + token
        if suffix is not None:
            if not isinstance(suffix, bytes):
                raise TypeError("Suffix must be a bytes")
            token = token + suffix
        return token
    elif format is Format.HEX:
        token = secrets.token_hex(nbytes)
        if prefix is not None:
            if not isinstance(prefix, str):
                raise TypeError("Prefix must be a string")
            token = prefix + token
        if suffix is not None:
            if not isinstance(suffix, str):
                raise TypeError("Suffix must be a string")
            token = token + suffix
        return token
    elif format is Format.STRING:
        token = secrets.token_urlsafe(nbytes)
        if prefix is not None:
            if not isinstance(prefix, str):
                raise TypeError("Prefix must be a string")
            token = prefix + token
        if suffix is not None:
            if not isinstance(suffix, str):
                raise TypeError("Suffix must be a string")
            token = token + suffix
        return token
