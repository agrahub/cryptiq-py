from base64 import b64decode, b64encode
from typing import overload

from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature import pkcs1_15
from typal.unions import BytesOrStr

from .hashes.enums import Mode
from .hashes.sha256 import hash


@overload
def sign(message: bytes, key: RsaKey) -> bytes: ...
@overload
def sign(message: str, key: RsaKey) -> str: ...
def sign(message: BytesOrStr, key: RsaKey) -> BytesOrStr:
    """
    Create an RSA PKCS#1 v1.5 digital signature for a message.

    This function hashes the provided message using SHA256 and signs
    the resulting digest using the provided RSA private key.

    The generated signature is Base64-encoded before being returned.

    The return type matches the message input type:
    - `bytes` input returns signature bytes
    - `str` input returns signature string

    Args:
        message:
            Message content to sign.

        key:
            RSA private key used for signature generation.

    Returns:
        A Base64-encoded RSA signature.

    Raises:
        TypeError:
            If the provided message type is unsupported.

        ValueError:
            If signature generation fails or the key is invalid.

    Notes:
        This function uses:
        - SHA256 as the hashing algorithm
        - PKCS#1 v1.5 as the signature scheme

    Example:
        >>> signature = sign("hello world", private_key)
    """
    sha256_hash = hash(Mode.OBJECT, message=message)
    signature = b64encode(pkcs1_15.new(key).sign(sha256_hash))
    if isinstance(message, bytes):
        return signature
    else:
        return signature.decode()


@overload
def verify(key: RsaKey, message: bytes, signature: bytes) -> bool: ...
@overload
def verify(key: RsaKey, message: str, signature: str) -> bool: ...
def verify(key: RsaKey, message: BytesOrStr, signature: BytesOrStr) -> bool:
    """
    Verify an RSA PKCS#1 v1.5 digital signature.

    This function recomputes the SHA256 hash of the provided message
    and verifies the supplied Base64-encoded signature using the
    provided RSA public key.

    Args:
        key:
            RSA public key used for signature verification.

        message:
            Original message associated with the signature.

        signature:
            Base64-encoded RSA signature to verify.

    Returns:
        `True` if the signature is valid, otherwise `False`.

    Raises:
        TypeError:
            If the provided argument types are unsupported.

    Notes:
        This function uses:
        - SHA256 as the hashing algorithm
        - PKCS#1 v1.5 as the verification scheme

        Invalid signatures return `False` instead of raising exceptions.

    Example:
        >>> verify(public_key, "hello world", signature)
        True
    """
    sha256_hash = hash(Mode.OBJECT, message=message)
    if isinstance(signature, str):
        signature_bytes = signature.encode()
    else:
        signature_bytes = signature

    try:
        pkcs1_15.new(key).verify(sha256_hash, b64decode(signature_bytes))
        return True
    except ValueError:
        return False
