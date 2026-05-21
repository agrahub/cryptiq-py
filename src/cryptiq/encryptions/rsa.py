from base64 import b64decode, b64encode
from typing import overload

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey.RSA import RsaKey
from typal.unions import BytesOrStr


@overload
def encrypt(key: RsaKey, plaintext: bytes) -> bytes: ...
@overload
def encrypt(key: RsaKey, plaintext: str) -> str: ...
def encrypt(key: RsaKey, plaintext: BytesOrStr) -> BytesOrStr:
    """
    Encrypt a message using RSA OAEP with SHA256.

    This function encrypts plaintext using RSA with OAEP padding and
    SHA256 as the underlying hash function. The resulting ciphertext
    is Base64-encoded for safe transport and storage.

    Args:
        key:
            RSA public key used for encryption.

        plaintext:
            Message to encrypt. Strings are encoded using UTF-8.

    Returns:
        Base64-encoded ciphertext.

        - `bytes` if input plaintext is bytes
        - `str` if input plaintext is str

    Raises:
        ValueError:
            If encryption fails or the input is too large for the key size.

        TypeError:
            If the provided key is invalid or unsupported.

    Notes:
        This implementation uses:
        - RSA OAEP padding
        - SHA256 as the hash algorithm
        - Base64 encoding for output

    Example:
        >>> ciphertext = encrypt(public_key, "hello world")
    """
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)

    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode()
    else:
        plaintext_bytes = plaintext

    ciphertext_bytes = b64encode(cipher.encrypt(plaintext_bytes))

    if isinstance(plaintext, str):
        return ciphertext_bytes.decode()
    else:
        return ciphertext_bytes


@overload
def decrypt(key: RsaKey, ciphertext: bytes) -> bytes: ...
@overload
def decrypt(key: RsaKey, ciphertext: str) -> str: ...
def decrypt(key: RsaKey, ciphertext: BytesOrStr) -> BytesOrStr:
    """
    Decrypt an RSA OAEP-encrypted message using SHA256.

    This function decrypts a Base64-encoded RSA ciphertext using OAEP
    padding and SHA256 as the underlying hash function.

    Args:
        ciphertext:
            Base64-encoded encrypted message.

        key:
            RSA private key used for decryption.

    Returns:
        Decrypted plaintext.

        - `bytes` if input ciphertext is bytes
        - `str` if input ciphertext is str

    Raises:
        ValueError:
            If decryption fails, data is corrupted, or padding is invalid.

        TypeError:
            If the provided key is invalid or unsupported.

    Notes:
        This implementation expects:
        - RSA OAEP padding
        - SHA256 as the hash algorithm
        - Base64-encoded ciphertext input

    Example:
        >>> plaintext = decrypt(ciphertext, private_key)
    """
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)

    if isinstance(ciphertext, str):
        ciphertext_bytes = ciphertext.encode()
    else:
        ciphertext_bytes = ciphertext

    plaintext_bytes = cipher.decrypt(b64decode(ciphertext_bytes))

    if isinstance(ciphertext, str):
        return plaintext_bytes.decode()
    else:
        return plaintext_bytes
