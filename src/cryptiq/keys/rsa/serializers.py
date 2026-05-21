from pathlib import Path
from typing import Literal, overload

from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from typal.bytes import DoubleBytes, OptBytes
from typal.strings import DoubleStrs, OptStr
from typal.unions import BytesOrStr, PathOrStr

from ..enums import Format, KeyType
from .types import (
    CryptographyRSAKeyPair,
    PycryptodomeRSAKeyPair,
    RSAKeyPairTypes,
    RSAKeyTypes,
    RSAPrivateKeyTypes,
    RSAPublicKeyTypes,
)


@overload
def serialize_private(
    private: rsa.RSAPrivateKey,
    password: OptBytes = None,
    *,
    format: Literal[Format.BYTES],
    path: PathOrStr | None = None,
) -> bytes: ...
@overload
def serialize_private(
    private: rsa.RSAPrivateKey,
    password: OptBytes = None,
    *,
    format: Literal[Format.STRING],
    path: PathOrStr | None = None,
) -> str: ...
@overload
def serialize_private(
    private: rsa.RSAPrivateKey,
    password: OptBytes = None,
    *,
    format: None = None,
    path: PathOrStr | None = None,
) -> None: ...
@overload
def serialize_private(
    private: RSA.RsaKey,
    password: OptStr = None,
    *,
    format: Literal[Format.BYTES],
    path: PathOrStr | None = None,
) -> bytes: ...
@overload
def serialize_private(
    private: RSA.RsaKey,
    password: OptStr = None,
    *,
    format: Literal[Format.STRING],
    path: PathOrStr | None = None,
) -> str: ...
@overload
def serialize_private(
    private: RSA.RsaKey,
    password: OptStr = None,
    *,
    format: None = None,
    path: PathOrStr | None = None,
) -> None: ...
def serialize_private(
    private: RSAPrivateKeyTypes,
    password: BytesOrStr | None = None,
    *,
    format: Format | None = None,
    path: PathOrStr | None = None,
) -> BytesOrStr | None:
    """
    Serialize an RSA private key into PEM format.

    This function converts an RSA private key into PEM-encoded bytes
    and optionally encrypts the output using the provided password.

    Serialized output may be returned directly, written to disk,
    or both depending on the provided arguments.

    Args:
        private:
            RSA private key instance to serialize.

        password:
            Optional password used to encrypt the serialized private key.

        format:
            Output format for the serialized key.

            - `Format.BYTES` returns PEM bytes
            - `Format.STRING` returns PEM string
            - `None` returns nothing

        path:
            Optional filesystem path used to write the serialized key.

    Returns:
        Serialized private key content when a format is provided,
        otherwise `None`.

    Raises:
        TypeError:
            If the provided key type or password type is unsupported.

        ValueError:
            If serialization or encryption fails.

        OSError:
            If writing to disk fails.

    Notes:
        Private keys are serialized using:
        - PKCS#8 format
        - PEM encoding

        Encryption behavior differs between backends:
        - cryptography expects password bytes
        - PyCryptodome expects password strings

    Example:
        >>> pem = serialize_private(
        ...     private_key,
        ...     password="secret",
        ...     format=Format.STRING,
        ... )
    """
    if isinstance(private, rsa.RSAPrivateKey):
        password = password.encode() if isinstance(password, str) else password
        encryption_algorithm = (
            serialization.NoEncryption()
            if not password
            else serialization.BestAvailableEncryption(password)
        )
        private_bytes = private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )
    else:
        password = password.decode() if isinstance(password, bytes) else password
        private_bytes = private.export_key(
            passphrase=password,
            pkcs=8,
            protection="PBKDF2WithHMAC-SHA512AndAES256-CBC",
        )

    if path:
        Path(path).write_bytes(private_bytes)

    if format is Format.BYTES:
        return private_bytes
    elif format is Format.STRING:
        return private_bytes.decode()
    else:
        return None


@overload
def serialize_public(
    public: RSAPublicKeyTypes,
    *,
    format: Literal[Format.BYTES],
    path: PathOrStr | None = None,
) -> bytes: ...
@overload
def serialize_public(
    public: RSAPublicKeyTypes,
    *,
    format: Literal[Format.STRING],
    path: PathOrStr | None = None,
) -> str: ...
@overload
def serialize_public(
    public: RSAPublicKeyTypes,
    *,
    format: None = None,
    path: PathOrStr | None = None,
) -> None: ...
def serialize_public(
    public: RSAPublicKeyTypes,
    *,
    format: Format | None = None,
    path: PathOrStr | None = None,
) -> BytesOrStr | None:
    """
    Serialize an RSA public key into PEM format.

    This function converts an RSA public key into PEM-encoded bytes.

    Serialized output may be returned directly, written to disk,
    or both depending on the provided arguments.

    Args:
        public:
            RSA public key instance to serialize.

        format:
            Output format for the serialized key.

            - `Format.BYTES` returns PEM bytes
            - `Format.STRING` returns PEM string
            - `None` returns nothing

        path:
            Optional filesystem path used to write the serialized key.

    Returns:
        Serialized public key content when a format is provided,
        otherwise `None`.

    Raises:
        TypeError:
            If the provided key type is unsupported.

        ValueError:
            If serialization fails.

        OSError:
            If writing to disk fails.

    Notes:
        Public keys are serialized using:
        - SubjectPublicKeyInfo format
        - PEM encoding

    Example:
        >>> pem = serialize_public(
        ...     public_key,
        ...     format=Format.STRING,
        ... )
    """
    if isinstance(public, rsa.RSAPublicKey):
        public_bytes = public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        public_bytes = public.export_key()

    if path:
        Path(path).write_bytes(public_bytes)

    if format is Format.BYTES:
        return public_bytes
    elif format is Format.STRING:
        return public_bytes.decode()
    else:
        return None


@overload
def serialize(
    type: Literal[KeyType.PRIVATE],
    key: rsa.RSAPrivateKey,
    password: OptBytes = None,
    *,
    format: Literal[Format.BYTES],
    path: PathOrStr | None = None,
) -> bytes: ...
@overload
def serialize(
    type: Literal[KeyType.PRIVATE],
    key: rsa.RSAPrivateKey,
    password: OptBytes = None,
    *,
    format: Literal[Format.STRING],
    path: PathOrStr | None = None,
) -> str: ...
@overload
def serialize(
    type: Literal[KeyType.PRIVATE],
    key: rsa.RSAPrivateKey,
    password: OptBytes = None,
    *,
    format: None = None,
    path: PathOrStr | None = None,
) -> None: ...
@overload
def serialize(
    type: Literal[KeyType.PRIVATE],
    key: RSA.RsaKey,
    password: OptStr = None,
    *,
    format: Literal[Format.BYTES],
    path: PathOrStr | None = None,
) -> bytes: ...
@overload
def serialize(
    type: Literal[KeyType.PRIVATE],
    key: RSA.RsaKey,
    password: OptStr = None,
    *,
    format: Literal[Format.STRING],
    path: PathOrStr | None = None,
) -> str: ...
@overload
def serialize(
    type: Literal[KeyType.PRIVATE],
    key: RSA.RsaKey,
    password: OptStr = None,
    *,
    format: None = None,
    path: PathOrStr | None = None,
) -> None: ...
@overload
def serialize(
    type: Literal[KeyType.PUBLIC],
    key: RSAPublicKeyTypes,
    *,
    format: Literal[Format.BYTES],
    path: PathOrStr | None = None,
) -> bytes: ...
@overload
def serialize(
    type: Literal[KeyType.PUBLIC],
    key: RSAPublicKeyTypes,
    *,
    format: Literal[Format.STRING],
    path: PathOrStr | None = None,
) -> str: ...
@overload
def serialize(
    type: Literal[KeyType.PUBLIC],
    key: RSAPublicKeyTypes,
    *,
    format: None = None,
    path: PathOrStr | None = None,
) -> None: ...
def serialize(
    type: KeyType,
    key: RSAKeyTypes,
    password: BytesOrStr | None = None,
    *,
    format: Format | None = None,
    path: PathOrStr | None = None,
) -> BytesOrStr | None:
    """
    Serialize an RSA key into PEM format.

    This function dispatches serialization behavior based on the
    provided RSA key type.

    Serialized output may be returned directly, written to disk,
    or both depending on the provided arguments.

    Args:
        type:
            Type of RSA key to serialize.

        key:
            RSA key instance to serialize.

        password:
            Optional password used to encrypt private keys.

            Ignored for public keys.

        format:
            Output format for the serialized key.

        path:
            Optional filesystem path used to write the serialized key.

    Returns:
        Serialized key content when a format is provided,
        otherwise `None`.

    Raises:
        TypeError:
            If the provided key type or password type is unsupported.

        ValueError:
            If serialization or encryption fails.

        OSError:
            If writing to disk fails.

    Notes:
        Public key serialization ignores the `password` argument.

    Example:
        >>> pem = serialize(
        ...     KeyType.PRIVATE,
        ...     private_key,
        ...     format=Format.STRING,
        ... )
    """
    if type is KeyType.PRIVATE:
        return serialize_private(  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
            private=key,  # pyright: ignore[reportArgumentType]
            password=password,  # pyright: ignore[reportArgumentType]
            format=format,  # pyright: ignore[reportArgumentType]
            path=path,
        )
    else:
        return serialize_public(  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
            public=key,  # pyright: ignore[reportArgumentType]
            format=format,  # pyright: ignore[reportArgumentType]
            path=path,
        )


@overload
def serialize_pair(
    keys: CryptographyRSAKeyPair,
    password: OptBytes = None,
    *,
    format: Literal[Format.BYTES],
    private_path: PathOrStr | None = None,
    public_path: PathOrStr | None = None,
) -> DoubleBytes: ...
@overload
def serialize_pair(
    keys: CryptographyRSAKeyPair,
    password: OptBytes = None,
    *,
    format: Literal[Format.STRING],
    private_path: PathOrStr | None = None,
    public_path: PathOrStr | None = None,
) -> DoubleStrs: ...
@overload
def serialize_pair(
    keys: CryptographyRSAKeyPair,
    password: OptBytes = None,
    *,
    format: None = None,
    private_path: PathOrStr | None = None,
    public_path: PathOrStr | None = None,
) -> None: ...
@overload
def serialize_pair(
    keys: PycryptodomeRSAKeyPair,
    password: OptStr = None,
    *,
    format: Literal[Format.BYTES],
    private_path: PathOrStr | None = None,
    public_path: PathOrStr | None = None,
) -> DoubleBytes: ...
@overload
def serialize_pair(
    keys: PycryptodomeRSAKeyPair,
    password: OptStr = None,
    *,
    format: Literal[Format.STRING],
    private_path: PathOrStr | None = None,
    public_path: PathOrStr | None = None,
) -> DoubleStrs: ...
@overload
def serialize_pair(
    keys: PycryptodomeRSAKeyPair,
    password: OptStr = None,
    *,
    format: None = None,
    private_path: PathOrStr | None = None,
    public_path: PathOrStr | None = None,
) -> None: ...
def serialize_pair(
    keys: RSAKeyPairTypes,
    password: BytesOrStr | None = None,
    *,
    format: Format | None = None,
    private_path: PathOrStr | None = None,
    public_path: PathOrStr | None = None,
) -> DoubleBytes | DoubleStrs | None:
    """
    Serialize an RSA private and public key pair into PEM format.

    This function serializes both RSA keys independently and returns
    them as a tuple preserving the `(private_key, public_key)` ordering.

    Serialized keys may also be written to disk using separate output
    paths.

    Args:
        keys:
            Tuple containing RSA private and public keys.

        password:
            Optional password used to encrypt the private key.

        format:
            Output format for serialized keys.

        private_path:
            Optional filesystem path used to write the serialized
            private key.

        public_path:
            Optional filesystem path used to write the serialized
            public key.

    Returns:
        A tuple containing serialized private and public keys when a
        format is provided, otherwise `None`.

    Raises:
        TypeError:
            If the provided key types or password type are unsupported.

        ValueError:
            If serialization or encryption fails.

        OSError:
            If writing to disk fails.

    Notes:
        Public keys are never encrypted even when a password is provided.

    Example:
        >>> private_pem, public_pem = serialize_pair(
        ...     keys,
        ...     format=Format.STRING,
        ... )
    """
    private, public = keys
    serialized_private = serialize_private(  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
        private=private,  # pyright: ignore[reportArgumentType]
        password=password,  # pyright: ignore[reportArgumentType]
        format=format,  # pyright: ignore[reportArgumentType]
        path=private_path,
    )
    serialized_public = serialize_public(  # pyright: ignore[reportUnknownVariableType]
        public=public,
        format=format,
        path=public_path,
    )
    if serialized_private is None and serialized_public is None:
        return None
    return serialized_private, serialized_public  # pyright: ignore[reportUnknownVariableType, reportReturnType]
