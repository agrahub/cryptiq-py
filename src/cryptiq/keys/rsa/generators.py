from typing import Literal, overload

from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from ...enums import Backend
from .types import (
    CryptographyRSAKeyPair,
    KeySize,
    PycryptodomeRSAKeyPair,
    RSAKeyPairTypes,
    RSAPrivateKeyTypes,
    RSAPublicKeyTypes,
)


@overload
def generate_private(
    backend: Literal[Backend.CRYPTOGRAPHY],
    *,
    size: KeySize = 2048,
) -> rsa.RSAPrivateKey: ...
@overload
def generate_private(
    backend: Literal[Backend.PYCRYPTODOME] = Backend.PYCRYPTODOME,
    *,
    size: KeySize = 2048,
) -> RSA.RsaKey: ...
def generate_private(
    backend: Backend = Backend.PYCRYPTODOME,
    *,
    size: KeySize = 2048,
) -> RSAPrivateKeyTypes:
    """
    Generate an RSA private key using the selected backend.

    This function creates a new RSA private key using either the
    `cryptography` or `PyCryptodome` backend implementation.

    Args:
        backend:
            Cryptographic backend used for RSA key generation.

        size:
            RSA modulus size in bits.

    Returns:
        A backend-specific RSA private key instance.

        - `rsa.RSAPrivateKey` for the cryptography backend
        - `RSA.RsaKey` for the PyCryptodome backend

    Raises:
        ValueError:
            If the provided key size is invalid or unsupported.

        TypeError:
            If the backend type is unsupported.

    Notes:
        All generated keys use a public exponent value of `65537`,
        which is the industry-standard RSA exponent.

    Example:
        >>> private_key = generate_private(size=4096)
    """
    if backend is Backend.CRYPTOGRAPHY:
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
            backend=default_backend(),
        )
    elif backend is Backend.PYCRYPTODOME:
        return RSA.generate(bits=size, e=65537)


@overload
def generate_public(*, private: rsa.RSAPrivateKey) -> rsa.RSAPublicKey: ...
@overload
def generate_public(*, private: RSA.RsaKey) -> RSA.RsaKey: ...
def generate_public(*, private: RSAPrivateKeyTypes) -> RSAPublicKeyTypes:
    """
    Generate an RSA public key from a private key.

    This function derives the corresponding public key from an
    existing RSA private key instance.

    Args:
        private:
            RSA private key used to derive the public key.

    Returns:
        A backend-specific RSA public key instance.

        - `rsa.RSAPublicKey` for cryptography private keys
        - `RSA.RsaKey` for PyCryptodome private keys

    Raises:
        TypeError:
            If the provided private key type is unsupported.

    Notes:
        The generated public key is mathematically derived from the
        provided private key and does not create a new key pair.

    Example:
        >>> public_key = generate_public(private=private_key)
    """
    if isinstance(private, rsa.RSAPrivateKey):
        return private.public_key()
    else:
        return private.publickey()


@overload
def generate_pair(
    backend: Literal[Backend.CRYPTOGRAPHY],
    *,
    size: KeySize = 2048,
) -> CryptographyRSAKeyPair: ...
@overload
def generate_pair(
    backend: Literal[Backend.PYCRYPTODOME] = Backend.PYCRYPTODOME,
    *,
    size: KeySize = 2048,
) -> PycryptodomeRSAKeyPair: ...
def generate_pair(
    backend: Backend = Backend.PYCRYPTODOME,
    *,
    size: KeySize = 2048,
) -> RSAKeyPairTypes:
    """
    Generate an RSA private and public key pair.

    This function creates a new RSA private key and derives its
    corresponding public key using the selected cryptographic backend.

    Args:
        backend:
            Cryptographic backend used for key generation.

        size:
            RSA modulus size in bits.

    Returns:
        A tuple containing the generated private and public keys.

    Raises:
        ValueError:
            If the provided key size is invalid or unsupported.

        TypeError:
            If the backend type is unsupported.

    Notes:
        The returned tuple preserves the ordering:
        `(private_key, public_key)`.

    Example:
        >>> private_key, public_key = generate_pair(size=3072)
    """
    private = generate_private(backend, size=size)
    public = generate_public(private=private)
    return (private, public)  # pyright: ignore[reportReturnType]
