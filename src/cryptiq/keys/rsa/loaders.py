from pathlib import Path
from typing import Literal, overload

from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from typal.bytes import OptBytes
from typal.strings import OptStr
from typal.unions import BytesOrStr, PathOrStr

from ...enums import Backend
from ..enums import KeyType
from .types import (
    CryptographyRSAKeyPair,
    PycryptodomeRSAKeyPair,
    RSAKeyPairTypes,
    RSAKeyTypes,
    RSAPrivateKeyTypes,
    RSAPublicKeyTypes,
)


@overload
def load_private(
    backend: Literal[Backend.CRYPTOGRAPHY],
    *,
    path: PathOrStr,
    password: OptBytes = None,
) -> rsa.RSAPrivateKey: ...
@overload
def load_private(
    backend: Literal[Backend.PYCRYPTODOME] = Backend.PYCRYPTODOME,
    *,
    path: PathOrStr,
    password: OptStr = None,
) -> RSA.RsaKey: ...
def load_private(
    backend: Backend = Backend.PYCRYPTODOME,
    *,
    path: PathOrStr,
    password: BytesOrStr | None = None,
) -> RSAPrivateKeyTypes:
    """
    Load an RSA private key from a PEM-encoded file.

    This function deserializes an RSA private key using the selected
    cryptographic backend implementation.

    Encrypted private keys are supported by providing the corresponding
    password.

    Args:
        backend:
            Cryptographic backend used for key deserialization.

        path:
            Filesystem path to the PEM-encoded private key file.

        password:
            Password used to decrypt the private key if encrypted.

    Returns:
        A backend-specific RSA private key instance.

        - `rsa.RSAPrivateKey` for the cryptography backend
        - `RSA.RsaKey` for the PyCryptodome backend

    Raises:
        FileNotFoundError:
            If the provided path does not exist.

        ValueError:
            If the key data is malformed or the password is incorrect.

        TypeError:
            If the loaded key is not an RSA private key or the key
            format is unsupported.

    Notes:
        Password encoding behavior differs between backends:

        - cryptography expects password bytes
        - PyCryptodome expects password strings

    Example:
        >>> private_key = load_private(
        ...     path="private.pem",
        ...     password="secret",
        ... )
    """
    data = Path(path).read_bytes()
    if backend is Backend.CRYPTOGRAPHY:
        password = password.encode() if isinstance(password, str) else password
        key = serialization.load_pem_private_key(data, password)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError("Expected RSA private key")
        return key
    else:
        password = password.decode() if isinstance(password, bytes) else password
        key = RSA.import_key(data, password)
        if not key.has_private():
            raise TypeError(
                "Invalid chosen key type, the private key did not contain private data"
            )
        return key


@overload
def load_public(
    backend: Literal[Backend.CRYPTOGRAPHY],
    *,
    path: PathOrStr,
) -> rsa.RSAPublicKey: ...
@overload
def load_public(
    backend: Literal[Backend.PYCRYPTODOME] = Backend.PYCRYPTODOME,
    *,
    path: PathOrStr,
) -> RSA.RsaKey: ...
def load_public(
    backend: Backend = Backend.PYCRYPTODOME,
    *,
    path: PathOrStr,
) -> RSAPublicKeyTypes:
    """
    Load an RSA public key from a PEM-encoded file.

    This function deserializes an RSA public key using the selected
    cryptographic backend implementation.

    Args:
        backend:
            Cryptographic backend used for key deserialization.

        path:
            Filesystem path to the PEM-encoded public key file.

    Returns:
        A backend-specific RSA public key instance.

        - `rsa.RSAPublicKey` for the cryptography backend
        - `RSA.RsaKey` for the PyCryptodome backend

    Raises:
        FileNotFoundError:
            If the provided path does not exist.

        ValueError:
            If the key data is malformed or invalid.

        TypeError:
            If the loaded key is not an RSA public key or the key
            format is unsupported.

    Notes:
        Public keys must not contain private key material.

    Example:
        >>> public_key = load_public(path="public.pem")
    """
    data = Path(path).read_bytes()
    if backend is Backend.CRYPTOGRAPHY:
        key = serialization.load_pem_public_key(data)
        if not isinstance(key, rsa.RSAPublicKey):
            raise TypeError("Expected RSA public key")
        return key
    else:
        key = RSA.import_key(data)
        if key.has_private():
            raise TypeError(
                "Invalid chosen key type, the public key contained private data"
            )
        return key


@overload
def load(
    type: Literal[KeyType.PRIVATE],
    backend: Literal[Backend.CRYPTOGRAPHY],
    *,
    path: PathOrStr,
    password: OptBytes = None,
) -> rsa.RSAPrivateKey: ...
@overload
def load(
    type: Literal[KeyType.PRIVATE],
    backend: Literal[Backend.PYCRYPTODOME] = Backend.PYCRYPTODOME,
    *,
    path: PathOrStr,
    password: OptStr = None,
) -> RSA.RsaKey: ...
@overload
def load(
    type: Literal[KeyType.PUBLIC],
    backend: Literal[Backend.CRYPTOGRAPHY],
    *,
    path: PathOrStr,
) -> rsa.RSAPublicKey: ...
@overload
def load(
    type: Literal[KeyType.PUBLIC],
    backend: Literal[Backend.PYCRYPTODOME] = Backend.PYCRYPTODOME,
    *,
    path: PathOrStr,
) -> RSA.RsaKey: ...
def load(
    type: KeyType,
    backend: Backend = Backend.PYCRYPTODOME,
    *,
    path: PathOrStr,
    password: BytesOrStr | None = None,
) -> RSAKeyTypes:
    """
    Load an RSA key from a PEM-encoded file.

    This function dispatches RSA key loading behavior based on the
    provided key type and backend implementation.

    Args:
        type:
            Type of RSA key to load.

        backend:
            Cryptographic backend used for key deserialization.

        path:
            Filesystem path to the PEM-encoded key file.

        password:
            Password used to decrypt private keys if encrypted.

            Ignored when loading public keys.

    Returns:
        A backend-specific RSA key instance.

    Raises:
        FileNotFoundError:
            If the provided path does not exist.

        ValueError:
            If the key data is malformed or the password is incorrect.

        TypeError:
            If the loaded key type is invalid or unsupported.

    Notes:
        Public key loading ignores the `password` argument entirely.

    Example:
        >>> private_key = load(
        ...     KeyType.PRIVATE,
        ...     path="private.pem",
        ... )
    """
    if type is KeyType.PRIVATE:
        return load_private(backend, path=path, password=password)  # pyright: ignore[reportUnknownVariableType, reportArgumentType, reportCallIssue]
    elif type is KeyType.PUBLIC:
        return load_public(backend, path=path)


@overload
def load_pair(
    backend: Literal[Backend.CRYPTOGRAPHY],
    *,
    private_path: PathOrStr,
    public_path: PathOrStr,
    password: OptBytes = None,
) -> CryptographyRSAKeyPair: ...
@overload
def load_pair(
    backend: Literal[Backend.PYCRYPTODOME] = Backend.PYCRYPTODOME,
    *,
    private_path: PathOrStr,
    public_path: PathOrStr,
    password: OptStr = None,
) -> PycryptodomeRSAKeyPair: ...
def load_pair(
    backend: Backend = Backend.PYCRYPTODOME,
    *,
    private_path: PathOrStr,
    public_path: PathOrStr,
    password: BytesOrStr | None = None,
) -> RSAKeyPairTypes:
    """
    Load an RSA private and public key pair from disk.

    This function loads both RSA keys using the selected cryptographic
    backend and returns them as a tuple preserving the
    `(private_key, public_key)` ordering.

    Args:
        backend:
            Cryptographic backend used for key deserialization.

        private_path:
            Filesystem path to the PEM-encoded private key file.

        public_path:
            Filesystem path to the PEM-encoded public key file.

        password:
            Password used to decrypt the private key if encrypted.

    Returns:
        A tuple containing the loaded RSA private and public keys.

    Raises:
        FileNotFoundError:
            If either key path does not exist.

        ValueError:
            If the key data is malformed or the password is incorrect.

        TypeError:
            If the loaded key type is invalid or unsupported.

    Notes:
        Both keys must be compatible with the selected backend.

    Example:
        >>> private_key, public_key = load_pair(
        ...     private_path="private.pem",
        ...     public_path="public.pem",
        ... )
    """
    private_key = load_private(backend, path=private_path, password=password)  # pyright: ignore[reportUnknownVariableType, reportCallIssue, reportArgumentType]
    public_key = load_public(backend, path=public_path)
    return private_key, public_key  # pyright: ignore[reportUnknownVariableType, reportReturnType]
