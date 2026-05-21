from pathlib import Path
from typing import Literal, overload

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from typal.unions import BytesOrStr, PathOrStr

from .enums import KeyType
from .types import KeyPairTypes, PrivateOrPublicKeyTypes


def load_private(
    path: PathOrStr, password: BytesOrStr | None = None
) -> PrivateKeyTypes:
    """
    Load a PEM-encoded private key from disk.

    This function reads a PEM-formatted private key file and deserializes
    it into a cryptography private key object.

    Encrypted private keys are supported by providing the corresponding
    password.

    Args:
        path:
            Filesystem path to the PEM-encoded private key file.

        password:
            Password used to decrypt the private key if the key is encrypted.

    Returns:
        The loaded private key instance.

    Raises:
        FileNotFoundError:
            If the provided path does not exist.

        ValueError:
            If the key data is malformed or the password is incorrect.

        TypeError:
            If the password type or key format is unsupported.

    Notes:
        String passwords are automatically encoded using UTF-8 before
        deserialization.

    Example:
        >>> private_key = load_private("private.pem", password="secret")
    """
    data = Path(path).read_bytes()
    password = password.encode() if isinstance(password, str) else password
    return serialization.load_pem_private_key(data, password)


def load_public(path: PathOrStr) -> PublicKeyTypes:
    """
    Load a PEM-encoded public key from disk.

    This function reads a PEM-formatted public key file and deserializes
    it into a cryptography public key object.

    Args:
        path:
            Filesystem path to the PEM-encoded public key file.

    Returns:
        The loaded public key instance.

    Raises:
        FileNotFoundError:
            If the provided path does not exist.

        ValueError:
            If the key data is malformed or invalid.

        TypeError:
            If the key format is unsupported.

    Example:
        >>> public_key = load_public("public.pem")
    """
    data = Path(path).read_bytes()
    return serialization.load_pem_public_key(data)


@overload
def load(
    type: Literal[KeyType.PRIVATE],
    *,
    path: PathOrStr,
    password: BytesOrStr | None = None,
) -> PrivateKeyTypes: ...
@overload
def load(
    type: Literal[KeyType.PUBLIC],
    *,
    path: PathOrStr,
) -> PublicKeyTypes: ...
def load(
    type: KeyType,
    *,
    path: PathOrStr,
    password: BytesOrStr | None = None,
) -> PrivateOrPublicKeyTypes:
    """
    Load either a private or public PEM key from disk.

    This function dispatches key loading behavior based on the provided
    key type and returns the corresponding deserialized key object.

    Args:
        type:
            Type of key to load.

        path:
            Filesystem path to the PEM-encoded key file.

        password:
            Password used to decrypt the private key if encrypted.

            Ignored when loading public keys.

    Returns:
        The loaded private or public key instance.

    Raises:
        FileNotFoundError:
            If the provided path does not exist.

        ValueError:
            If the key data is malformed or the password is incorrect.

        TypeError:
            If the password type or key format is unsupported.

    Notes:
        Public keys do not require passwords and ignore the `password`
        argument entirely.

    Example:
        >>> private_key = load(KeyType.PRIVATE, path="private.pem")
    """
    if type is KeyType.PRIVATE:
        return load_private(path, password)
    elif type is KeyType.PUBLIC:
        return load_public(path)


def load_pair(
    private_path: PathOrStr, public_path: PathOrStr, password: BytesOrStr | None = None
) -> KeyPairTypes:
    """
    Load a PEM-encoded private and public key pair from disk.

    This function loads both keys independently and returns them as a
    tuple preserving the `(private_key, public_key)` ordering.

    Args:
        private_path:
            Filesystem path to the PEM-encoded private key file.

        public_path:
            Filesystem path to the PEM-encoded public key file.

        password:
            Password used to decrypt the private key if encrypted.

    Returns:
        A tuple containing the loaded private and public key instances.

    Raises:
        FileNotFoundError:
            If either key path does not exist.

        ValueError:
            If the key data is malformed or the password is incorrect.

        TypeError:
            If the password type or key format is unsupported.

    Example:
        >>> private_key, public_key = load_pair(
        ...     "private.pem",
        ...     "public.pem",
        ... )
    """
    private_key = load_private(private_path, password)
    public_key = load_public(public_path)
    return private_key, public_key
