from typing import Literal, overload

from Crypto.Hash import SHA256
from typal.unions import BytesOrStr

from .enums import Mode


@overload
def hash(
    mode: Literal[Mode.OBJECT],
    *,
    message: BytesOrStr,
) -> SHA256.SHA256Hash: ...
@overload
def hash(
    mode: Literal[Mode.DIGEST] = Mode.DIGEST,
    *,
    message: bytes,
) -> bytes: ...
@overload
def hash(
    mode: Literal[Mode.DIGEST] = Mode.DIGEST,
    *,
    message: str,
) -> str: ...
def hash(
    mode: Mode = Mode.DIGEST,
    *,
    message: BytesOrStr,
) -> SHA256.SHA256Hash | BytesOrStr:
    """
    Compute a SHA256 cryptographic hash for a message.

    This function generates a SHA256 hash from the provided message and
    supports returning either the finalized digest or the underlying
    SHA256 hash object.

    The returned digest type matches the message input type:
    - `bytes` input returns raw digest bytes
    - `str` input returns hexadecimal digest string

    Args:
        mode:
            Output mode controlling the returned value.

            - `Mode.DIGEST` returns the finalized digest
            - `Mode.OBJECT` returns the underlying SHA256 object

        message:
            Message content to hash.

    Returns:
        One of the following values depending on mode and input type:

        - `SHA256.SHA256Hash` when `mode` is `Mode.OBJECT`
        - `bytes` digest when message input is `bytes`
        - `str` hexadecimal digest when message input is `str`

    Raises:
        TypeError:
            If `message` is not a supported type.

    Notes:
        SHA256 is a deterministic cryptographic hash function and does
        not provide encryption or authentication guarantees.

    Example:
        >>> digest = hash(message="hello world")
    """
    if isinstance(message, str):
        message_bytes = message.encode()
    else:
        message_bytes = message

    hash = SHA256.new(message_bytes)

    if mode is Mode.OBJECT:
        return hash

    if isinstance(message, str):
        return hash.hexdigest()
    else:
        return hash.digest()


@overload
def verify(
    message: BytesOrStr,
    message_hash: SHA256.SHA256Hash,
) -> bool: ...
@overload
def verify(
    message: bytes,
    message_hash: bytes,
) -> bool: ...
@overload
def verify(
    message: str,
    message_hash: str,
) -> bool: ...
def verify(
    message: BytesOrStr,
    message_hash: SHA256.SHA256Hash | BytesOrStr,
) -> bool:
    """
    Verify a SHA256 hash against a message.

    This function recomputes the SHA256 hash for the provided message
    and compares it against the supplied hash value.

    Supported verification formats include:
    - SHA256 hash object instances
    - Raw digest bytes
    - Hexadecimal digest strings

    Args:
        message:
            Original message to verify.

        message_hash:
            Expected SHA256 hash value.

    Returns:
        `True` if the computed hash matches the provided hash,
        otherwise `False`.

    Raises:
        TypeError:
            If provided arguments are not supported types.

    Notes:
        SHA256 hashing is deterministic, meaning identical messages
        always produce identical hash outputs.

    Example:
        >>> verify("hello world", digest)
        True
    """
    computed_hash = hash(Mode.OBJECT, message=message)

    if isinstance(message_hash, str):
        return computed_hash.hexdigest() == message_hash
    elif isinstance(message_hash, bytes):
        return computed_hash.digest() == message_hash
    else:
        return computed_hash.digest() == message_hash.digest()
