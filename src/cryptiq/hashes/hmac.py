from typing import Literal, overload

from Crypto.Hash import HMAC, SHA256
from typal.unions import BytesOrStr

from .enums import Mode


@overload
def hash(
    mode: Literal[Mode.OBJECT],
    *,
    key: BytesOrStr,
    message: BytesOrStr,
) -> HMAC.HMAC: ...
@overload
def hash(
    mode: Literal[Mode.DIGEST] = Mode.DIGEST,
    *,
    key: bytes,
    message: bytes,
) -> bytes: ...
@overload
def hash(
    mode: Literal[Mode.DIGEST] = Mode.DIGEST,
    *,
    key: str,
    message: str,
) -> str: ...
def hash(
    mode: Mode = Mode.DIGEST,
    *,
    key: BytesOrStr,
    message: BytesOrStr,
) -> HMAC.HMAC | BytesOrStr:
    """
    Compute an HMAC-SHA256 authentication hash for a message.

    This function generates an HMAC using SHA256 as the underlying
    digest algorithm. It supports returning either the raw HMAC object
    or the finalized digest value depending on the selected mode.

    The returned digest type matches the message input type:
    - `bytes` input returns raw digest bytes
    - `str` input returns hexadecimal digest string

    Args:
        mode:
            Output mode controlling the returned value.

            - `Mode.DIGEST` returns the finalized digest
            - `Mode.OBJECT` returns the underlying HMAC object

        key:
            Secret key used to generate the HMAC.

        message:
            Message content to authenticate.

    Returns:
        One of the following values depending on mode and input type:

        - `HMAC.HMAC` when `mode` is `Mode.OBJECT`
        - `bytes` digest when message input is `bytes`
        - `str` hexadecimal digest when message input is `str`

    Raises:
        TypeError:
            If provided arguments are not supported types.

    Notes:
        HMAC provides integrity verification and authentication but does
        not encrypt the underlying message.

    Example:
        >>> digest = hash(key="secret", message="hello")
    """
    if isinstance(key, str):
        key_bytes = key.encode()
    else:
        key_bytes = key

    if isinstance(message, str):
        message_bytes = message.encode()
    else:
        message_bytes = message

    hash = HMAC.new(key=key_bytes, msg=message_bytes, digestmod=SHA256)

    if mode is Mode.OBJECT:
        return hash

    if isinstance(message, str):
        return hash.hexdigest()
    else:
        return hash.digest()


@overload
def verify(
    key: bytes,
    message: bytes,
    message_hash: HMAC.HMAC,
) -> bool: ...
@overload
def verify(
    key: bytes,
    message: bytes,
    message_hash: bytes,
) -> bool: ...
@overload
def verify(
    key: str,
    message: str,
    message_hash: str,
) -> bool: ...
def verify(
    key: BytesOrStr,
    message: BytesOrStr,
    message_hash: HMAC.HMAC | BytesOrStr,
) -> bool:
    """
    Verify an HMAC-SHA256 hash against a key and message pair.

    This function recomputes the HMAC for the provided key and message
    and compares it against the supplied authentication hash.

    Supported verification formats include:
    - HMAC object instances
    - Raw digest bytes
    - Hexadecimal digest strings

    Args:
        key:
            Secret key used to generate the HMAC.

        message:
            Original authenticated message.

        message_hash:
            Expected HMAC value to verify.

    Returns:
        `True` if the computed HMAC matches the provided hash,
        otherwise `False`.

    Raises:
        TypeError:
            If provided arguments are not supported types.

    Notes:
        Verification uses SHA256 as the underlying digest algorithm.

    Example:
        >>> verify("secret", "hello", digest)
        True
    """
    computed_hash = hash(Mode.OBJECT, key=key, message=message)

    if isinstance(message_hash, str):
        return computed_hash.hexdigest() == message_hash
    elif isinstance(message_hash, bytes):
        return computed_hash.digest() == message_hash
    else:
        return computed_hash.digest() == message_hash.digest()
