from typing import Annotated, ClassVar, Literal, overload

from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import BaseModel, ConfigDict, Field
from typal.bytes import DoubleBytes, OptBytes
from typal.strings import DoubleStrs, OptStr
from typal.unions import BytesOrStr, PathOrStr

from ...enums import Backend
from ..enums import Format
from .generators import generate_pair
from .loaders import load_pair
from .serializers import serialize_pair
from .types import (
    KeySize,
    RSAPrivateKeyTypes,
    RSAPublicKeyTypes,
)


class RSAKeys[
    R: RSAPrivateKeyTypes,
    U: RSAPublicKeyTypes,
](BaseModel):
    """
    Generic RSA key container model.

    This class represents a strongly-typed RSA key pair and provides
    unified APIs for generating, loading, and serializing RSA keys
    across multiple cryptographic backends.

    The model is parameterized by:
    - R: private key type
    - U: public key type

    Attributes:
        backend (ClassVar[Backend]):
            Cryptographic backend associated with this key type.

        private (R):
            RSA private key instance.

        public (U):
            RSA public key instance.

    Notes:
        This class is designed as a base abstraction and should not be
        instantiated directly. Use backend-specific subclasses instead.

    Example:
        >>> keys = CryptographyRSAKeys.generate()
        >>> keys.private
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    backend: ClassVar[Backend]

    private: Annotated[R, Field(description="The RSA private key in PEM format.")]
    public: Annotated[U, Field(description="The RSA public key in PEM format.")]

    @classmethod
    def generate(cls, size: KeySize = 2048) -> RSAKeys[R, U]:
        """
        Generate a new RSA key pair.

        This class method generates a fresh RSA private/public key pair
        using the backend associated with the concrete subclass.

        Args:
            size:
                RSA key size in bits.

        Returns:
            A new RSAKeys instance containing generated keys.

        Raises:
            ValueError:
                If the key size is invalid.

        Example:
            >>> keys = CryptographyRSAKeys.generate(size=3072)
        """
        private, public = generate_pair(cls.backend, size=size)
        return cls(private=private, public=public)  # pyright: ignore[reportArgumentType]

    @classmethod
    def load(
        cls,
        private_path: PathOrStr,
        public_path: PathOrStr,
        password: BytesOrStr | None = None,
    ) -> RSAKeys[R, U]:
        """
        Load an RSA key pair from disk.

        This method loads both private and public keys from PEM files
        and constructs a strongly-typed RSA key container.

        Args:
            private_path:
                Path to the PEM-encoded private key file.

            public_path:
                Path to the PEM-encoded public key file.

            password:
                Optional password used to decrypt the private key.

        Returns:
            An RSAKeys instance containing loaded keys.

        Raises:
            FileNotFoundError:
                If either key file does not exist.

            ValueError:
                If key files are malformed or invalid.

        Example:
            >>> keys = CryptographyRSAKeys.load(
            ...     "private.pem",
            ...     "public.pem",
            ... )
        """
        private, public = load_pair(  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
            cls.backend,  # pyright: ignore[reportArgumentType]
            private_path=private_path,
            public_path=public_path,
            password=password,  # pyright: ignore[reportArgumentType]
        )
        return cls(private=private, public=public)  # pyright: ignore[reportUnknownArgumentType]

    @overload
    def serialize(
        self,
        password: BytesOrStr | None = None,
        *,
        format: Literal[Format.BYTES],
        private_path: PathOrStr | None = None,
        public_path: PathOrStr | None = None,
    ) -> DoubleBytes: ...
    @overload
    def serialize(
        self,
        password: BytesOrStr | None = None,
        *,
        format: Literal[Format.STRING],
        private_path: PathOrStr | None = None,
        public_path: PathOrStr | None = None,
    ) -> DoubleStrs: ...
    @overload
    def serialize(
        self,
        password: BytesOrStr | None = None,
        *,
        format: None = None,
        private_path: PathOrStr | None = None,
        public_path: PathOrStr | None = None,
    ) -> None: ...
    def serialize(
        self,
        password: BytesOrStr | None = None,
        *,
        format: Format | None = None,
        private_path: PathOrStr | None = None,
        public_path: PathOrStr | None = None,
    ) -> DoubleBytes | DoubleStrs | None:
        """
        Serialize the RSA key pair.

        This method serializes both private and public keys using the
        selected output format and optionally writes them to disk.

        Args:
            password:
                Optional password used to encrypt the private key.

            format:
                Output format selection:
                - `Format.BYTES` returns PEM bytes
                - `Format.STRING` returns PEM strings
                - `None` returns nothing

            private_path:
                Optional path to write the serialized private key.

            public_path:
                Optional path to write the serialized public key.

        Returns:
            Serialized key pair when a format is provided, otherwise None.

        Raises:
            ValueError:
                If serialization fails.

            TypeError:
                If key or password types are invalid.

        Example:
            >>> pem_private, pem_public = keys.serialize(
            ...     format=Format.STRING
            ... )
        """
        return serialize_pair(  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
            (self.private, self.public),  # pyright: ignore[reportArgumentType]
            password=password,  # pyright: ignore[reportArgumentType]
            format=format,  # pyright: ignore[reportArgumentType]
            private_path=private_path,
            public_path=public_path,
        )


class CryptographyRSAKeys(RSAKeys[rsa.RSAPrivateKey, rsa.RSAPublicKey]):
    """
    RSA key container using the `cryptography` backend.

    This class implements RSA key management using the
    `cryptography` library backend.

    Notes:
        - Uses OpenSSL-backed cryptographic primitives
        - Keys are represented as `cryptography` RSA objects
    """

    backend = Backend.CRYPTOGRAPHY

    @overload
    def serialize(
        self,
        password: OptBytes = None,
        *,
        format: Literal[Format.BYTES],
        private_path: PathOrStr | None = None,
        public_path: PathOrStr | None = None,
    ) -> DoubleBytes: ...
    @overload
    def serialize(
        self,
        password: OptBytes = None,
        *,
        format: Literal[Format.STRING],
        private_path: PathOrStr | None = None,
        public_path: PathOrStr | None = None,
    ) -> DoubleStrs: ...
    @overload
    def serialize(
        self,
        password: OptBytes = None,
        *,
        format: None = None,
        private_path: PathOrStr | None = None,
        public_path: PathOrStr | None = None,
    ) -> None: ...
    def serialize(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
        password: OptBytes = None,
        *,
        format: Format | None = None,
        private_path: PathOrStr | None = None,
        public_path: PathOrStr | None = None,
    ) -> DoubleBytes | DoubleStrs | None:
        """
        Serialize a cryptography-based RSA key pair.

        This method overrides the base serializer to enforce byte-based
        password handling required by the cryptography backend.

        Args:
            password:
                Optional encryption password (bytes only).

            format:
                Output format selection.

            private_path:
                Optional private key output path.

            public_path:
                Optional public key output path.

        Returns:
            Serialized key pair or None.

        Example:
            >>> keys.serialize(format=Format.BYTES)
        """
        return serialize_pair(
            (self.private, self.public),
            password=password,
            format=format,
            private_path=private_path,
            public_path=public_path,
        )


class PycryptodomeRSAKeys(RSAKeys[RSA.RsaKey, RSA.RsaKey]):
    """
    RSA key container using the PyCryptodome backend.

    This class implements RSA key management using the PyCryptodome
    cryptographic library.

    Notes:
        - Uses PyCryptodome RSA implementation
        - Keys are represented as `Crypto.PublicKey.RSA.RsaKey`
    """

    backend = Backend.PYCRYPTODOME

    @overload
    def serialize(
        self,
        password: OptStr = None,
        *,
        format: Literal[Format.BYTES],
        private_path: PathOrStr | None = None,
        public_path: PathOrStr | None = None,
    ) -> DoubleBytes: ...
    @overload
    def serialize(
        self,
        password: OptStr = None,
        *,
        format: Literal[Format.STRING],
        private_path: PathOrStr | None = None,
        public_path: PathOrStr | None = None,
    ) -> DoubleStrs: ...
    @overload
    def serialize(
        self,
        password: OptStr = None,
        *,
        format: None = None,
        private_path: PathOrStr | None = None,
        public_path: PathOrStr | None = None,
    ) -> None: ...
    def serialize(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
        password: OptStr = None,
        *,
        format: Format | None = None,
        private_path: PathOrStr | None = None,
        public_path: PathOrStr | None = None,
    ) -> DoubleBytes | DoubleStrs | None:
        """
        Serialize a PyCryptodome-based RSA key pair.

        This method overrides the base serializer to enforce string-based
        password handling required by PyCryptodome.

        Args:
            password:
                Optional encryption password (string only).

            format:
                Output format selection.

            private_path:
                Optional private key output path.

            public_path:
                Optional public key output path.

        Returns:
            Serialized key pair or None.

        Example:
            >>> keys.serialize(format=Format.STRING)
        """
        return serialize_pair(
            (self.private, self.public),
            password=password,
            format=format,
            private_path=private_path,
            public_path=public_path,
        )
