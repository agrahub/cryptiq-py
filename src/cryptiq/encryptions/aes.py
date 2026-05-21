import os
from base64 import b64decode, b64encode
from typing import overload

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.decrepit.ciphers import modes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from typal.bytes import TripleBytes
from typal.strings import TripleStrs
from typal.unions import BytesOrStr


@overload
def encrypt(plaintext: bytes) -> TripleBytes: ...
@overload
def encrypt(plaintext: str) -> TripleStrs: ...
def encrypt(plaintext: BytesOrStr) -> TripleBytes | TripleStrs:
    """
    Encrypt plaintext using AES-256 in CFB mode.

    A random 256-bit encryption key and 128-bit initialization vector
    are generated for each encryption operation. The resulting key,
    initialization vector, and ciphertext are Base64-encoded before
    being returned.

    The return type matches the input type:
    - `bytes` input returns a tuple of `bytes`
    - `str` input returns a tuple of `str`

    Args:
        plaintext:
            Plaintext content to encrypt.

    Returns:
        A tuple containing:
        - Base64-encoded encryption key
        - Base64-encoded initialization vector
        - Base64-encoded ciphertext

    Raises:
        TypeError:
            If `plaintext` is not a supported type.

    Notes:
        A new random encryption key is generated on every call.

    Example:
        >>> key, iv, ciphertext = encrypt("hello world")
    """
    key_bytes = os.urandom(32)
    initialization_vector_bytes = os.urandom(16)

    cipher = Cipher(
        algorithm=algorithms.AES256(key_bytes),
        mode=modes.CFB(initialization_vector_bytes),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()

    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode()
    else:
        plaintext_bytes = plaintext

    ciphertext_bytes = b64encode(
        encryptor.update(plaintext_bytes) + encryptor.finalize()
    )

    key_bytes = b64encode(key_bytes)
    initialization_vector_bytes = b64encode(initialization_vector_bytes)

    if isinstance(plaintext, bytes):
        return (key_bytes, initialization_vector_bytes, ciphertext_bytes)
    else:
        return (
            key_bytes.decode(),
            initialization_vector_bytes.decode(),
            ciphertext_bytes.decode(),
        )


@overload
def decrypt(key: bytes, initialization_vector: bytes, ciphertext: bytes) -> bytes: ...
@overload
def decrypt(key: str, initialization_vector: str, ciphertext: str) -> str: ...
def decrypt(
    key: BytesOrStr, initialization_vector: BytesOrStr, ciphertext: BytesOrStr
) -> BytesOrStr:
    """
    Decrypt AES-256 CFB ciphertext using the provided key and
    initialization vector.

    The provided key, initialization vector, and ciphertext must be
    Base64-encoded values previously returned by `encrypt()`.

    The return type matches the ciphertext input type:
    - `bytes` ciphertext returns decrypted `bytes`
    - `str` ciphertext returns decrypted `str`

    Args:
        key:
            Base64-encoded AES encryption key.

        initialization_vector:
            Base64-encoded initialization vector used during encryption.

        ciphertext:
            Base64-encoded ciphertext to decrypt.

    Returns:
        The decrypted plaintext.

    Raises:
        ValueError:
            If Base64 decoding fails or the encrypted payload is invalid.

        TypeError:
            If the provided arguments are not supported types.

    Notes:
        This function assumes the encryption parameters were generated
        using AES-256 in CFB mode.

    Example:
        >>> plaintext = decrypt(key, iv, ciphertext)
    """
    if isinstance(key, str):
        key_bytes = key.encode()
    else:
        key_bytes = key

    key_bytes = b64decode(key_bytes)

    if isinstance(initialization_vector, str):
        initialization_vector_bytes = initialization_vector.encode()
    else:
        initialization_vector_bytes = initialization_vector

    initialization_vector_bytes = b64decode(initialization_vector_bytes)

    if isinstance(ciphertext, str):
        ciphertext_bytes = ciphertext.encode()
    else:
        ciphertext_bytes = ciphertext

    ciphertext_bytes = b64decode(ciphertext_bytes)

    cipher = Cipher(
        algorithm=algorithms.AES256(key_bytes),
        mode=modes.CFB(initialization_vector_bytes),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()

    plaintext_bytes = decryptor.update(ciphertext_bytes) + decryptor.finalize()

    if isinstance(ciphertext, bytes):
        return plaintext_bytes
    else:
        return plaintext_bytes.decode()
