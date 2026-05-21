from pathlib import Path

import pytest
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptiq.enums import Backend
from cryptiq.keys.enums import KeyType
from cryptiq.keys.rsa.generators import (
    generate_pair,
    generate_private,
    generate_public,
)
from cryptiq.keys.rsa.loaders import (
    load,
    load_pair,
    load_private,
    load_public,
)
from cryptiq.keys.rsa.models import (
    CryptographyRSAKeys,
    PycryptodomeRSAKeys,
)

# =========================================================
# Helpers
# =========================================================


def _write_pycryptodome_private(
    path: Path,
    private: RSA.RsaKey,
    *,
    password: str | None = None,
) -> None:
    if password is None:
        data = private.export_key()
    else:
        data = private.export_key(
            passphrase=password,
            pkcs=8,
            protection="scryptAndAES128-CBC",
        )

    path.write_bytes(data)


def _write_pycryptodome_public(
    path: Path,
    public: RSA.RsaKey,
) -> None:
    path.write_bytes(public.export_key())


def _write_cryptography_private(
    path: Path,
    private: rsa.RSAPrivateKey,
    *,
    password: bytes | None = None,
) -> None:
    if password is None:
        algorithm = serialization.NoEncryption()
    else:
        algorithm = serialization.BestAvailableEncryption(password)

    data = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=algorithm,
    )

    path.write_bytes(data)


def _write_cryptography_public(
    path: Path,
    public: rsa.RSAPublicKey,
) -> None:
    data = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    path.write_bytes(data)


# =========================================================
# PyCryptodome workflow integration
# =========================================================


def test_pycryptodome_generate_save_load_roundtrip(
    tmp_path: Path,
) -> None:
    private, public = generate_pair(
        Backend.PYCRYPTODOME,
    )

    assert isinstance(private, RSA.RsaKey)
    assert isinstance(public, RSA.RsaKey)

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    _write_pycryptodome_private(private_path, private)
    _write_pycryptodome_public(public_path, public)

    loaded_private = load_private(
        Backend.PYCRYPTODOME,
        path=private_path,
    )

    loaded_public = load_public(
        Backend.PYCRYPTODOME,
        path=public_path,
    )

    assert loaded_private.n == private.n
    assert loaded_private.d == private.d

    assert loaded_public.n == public.n
    assert loaded_public.e == public.e


def test_pycryptodome_generate_save_load_pair_roundtrip(
    tmp_path: Path,
) -> None:
    private, public = generate_pair(
        Backend.PYCRYPTODOME,
    )

    assert isinstance(private, RSA.RsaKey)
    assert isinstance(public, RSA.RsaKey)

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    _write_pycryptodome_private(private_path, private)
    _write_pycryptodome_public(public_path, public)

    loaded_private, loaded_public = load_pair(
        Backend.PYCRYPTODOME,
        private_path=private_path,
        public_path=public_path,
    )

    assert loaded_private.n == private.n
    assert loaded_public.n == public.n


def test_pycryptodome_generate_and_model_integration() -> None:
    private, public = generate_pair(
        Backend.PYCRYPTODOME,
    )

    model = PycryptodomeRSAKeys(
        private=private,
        public=public,
    )

    assert model.private.n == private.n
    assert model.public.n == public.n


# =========================================================
# Pycryptodome model workflow integration
# =========================================================


def test_pycryptodome_model_generate_integration() -> None:
    model = PycryptodomeRSAKeys.generate()

    assert isinstance(model, PycryptodomeRSAKeys)

    assert isinstance(model.private, RSA.RsaKey)
    assert isinstance(model.public, RSA.RsaKey)

    assert model.private.has_private()
    assert not model.public.has_private()

    assert model.private.n == model.public.n
    assert model.private.e == model.public.e


def test_pycryptodome_model_load_integration(
    tmp_path: Path,
) -> None:
    generated = PycryptodomeRSAKeys.generate()

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    _write_pycryptodome_private(
        private_path,
        generated.private,
    )

    _write_pycryptodome_public(
        public_path,
        generated.public,
    )

    loaded = PycryptodomeRSAKeys.load(
        private_path=private_path,
        public_path=public_path,
    )

    assert isinstance(loaded, PycryptodomeRSAKeys)

    assert loaded.private.has_private()
    assert not loaded.public.has_private()

    assert loaded.private.n == generated.private.n
    assert loaded.private.d == generated.private.d

    assert loaded.public.n == generated.public.n
    assert loaded.public.e == generated.public.e


def test_pycryptodome_model_load_encrypted_private_key_integration(
    tmp_path: Path,
) -> None:
    generated = PycryptodomeRSAKeys.generate()

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    _write_pycryptodome_private(
        private_path,
        generated.private,
        password="secret",
    )

    _write_pycryptodome_public(
        public_path,
        generated.public,
    )

    loaded = PycryptodomeRSAKeys.load(
        private_path=private_path,
        public_path=public_path,
        password="secret",
    )

    assert loaded.private.n == generated.private.n
    assert loaded.private.d == generated.private.d

    assert loaded.public.n == generated.public.n


# =========================================================
# Cryptography model workflow integration
# =========================================================


def test_cryptography_model_generate_integration() -> None:
    model = CryptographyRSAKeys.generate()

    assert isinstance(model, CryptographyRSAKeys)

    assert isinstance(model.private, rsa.RSAPrivateKey)
    assert isinstance(model.public, rsa.RSAPublicKey)

    private_numbers = model.private.private_numbers()
    public_numbers = model.public.public_numbers()

    assert private_numbers.public_numbers.n == public_numbers.n

    assert private_numbers.public_numbers.e == public_numbers.e


def test_cryptography_model_load_integration(
    tmp_path: Path,
) -> None:
    generated = CryptographyRSAKeys.generate()

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    _write_cryptography_private(
        private_path,
        generated.private,
    )

    _write_cryptography_public(
        public_path,
        generated.public,
    )

    loaded = CryptographyRSAKeys.load(
        private_path=private_path,
        public_path=public_path,
    )

    assert isinstance(loaded, CryptographyRSAKeys)

    loaded_private_numbers = loaded.private.private_numbers()

    generated_private_numbers = generated.private.private_numbers()

    loaded_public_numbers = loaded.public.public_numbers()

    generated_public_numbers = generated.public.public_numbers()

    assert (
        loaded_private_numbers.public_numbers.n
        == generated_private_numbers.public_numbers.n
    )

    assert loaded_private_numbers.d == generated_private_numbers.d

    assert loaded_public_numbers.n == generated_public_numbers.n

    assert loaded_public_numbers.e == generated_public_numbers.e


def test_cryptography_model_load_encrypted_private_key_integration(
    tmp_path: Path,
) -> None:
    generated = CryptographyRSAKeys.generate()

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    _write_cryptography_private(
        private_path,
        generated.private,
        password=b"secret",
    )

    _write_cryptography_public(
        public_path,
        generated.public,
    )

    loaded = CryptographyRSAKeys.load(
        private_path=private_path,
        public_path=public_path,
        password="secret",  # pyright: ignore[reportArgumentType]
    )

    loaded_private_numbers = loaded.private.private_numbers()

    generated_private_numbers = generated.private.private_numbers()

    assert (
        loaded_private_numbers.public_numbers.n
        == generated_private_numbers.public_numbers.n
    )

    assert loaded_private_numbers.d == generated_private_numbers.d

    assert loaded.public.public_numbers().n == generated.public.public_numbers().n


def test_pycryptodome_load_dispatcher_integration(
    tmp_path: Path,
) -> None:
    private, public = generate_pair(
        Backend.PYCRYPTODOME,
    )

    assert isinstance(private, RSA.RsaKey)
    assert isinstance(public, RSA.RsaKey)

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    _write_pycryptodome_private(private_path, private)
    _write_pycryptodome_public(public_path, public)

    loaded_private = load(
        KeyType.PRIVATE,
        Backend.PYCRYPTODOME,
        path=private_path,
    )

    loaded_public = load(
        KeyType.PUBLIC,
        Backend.PYCRYPTODOME,
        path=public_path,
    )

    assert isinstance(loaded_private, RSA.RsaKey)
    assert isinstance(loaded_public, RSA.RsaKey)

    assert loaded_private.has_private()
    assert not loaded_public.has_private()

    assert loaded_private.n == private.n
    assert loaded_public.n == public.n


def test_pycryptodome_encrypted_private_key_roundtrip(
    tmp_path: Path,
) -> None:
    private, public = generate_pair(
        Backend.PYCRYPTODOME,
    )

    assert isinstance(private, RSA.RsaKey)
    assert isinstance(public, RSA.RsaKey)

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    _write_pycryptodome_private(
        private_path,
        private,
        password="secret",
    )

    _write_pycryptodome_public(public_path, public)

    loaded_private, loaded_public = load_pair(
        Backend.PYCRYPTODOME,
        private_path=private_path,
        public_path=public_path,
        password="secret",
    )

    assert loaded_private.n == private.n
    assert loaded_private.d == private.d

    assert loaded_public.n == public.n


# =========================================================
# Cryptography workflow integration
# =========================================================


def test_cryptography_generate_save_load_roundtrip(
    tmp_path: Path,
) -> None:
    private, public = generate_pair(
        Backend.CRYPTOGRAPHY,
    )

    assert isinstance(private, rsa.RSAPrivateKey)
    assert isinstance(public, rsa.RSAPublicKey)

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    _write_cryptography_private(private_path, private)
    _write_cryptography_public(public_path, public)

    loaded_private = load_private(
        Backend.CRYPTOGRAPHY,
        path=private_path,
    )

    loaded_public = load_public(
        Backend.CRYPTOGRAPHY,
        path=public_path,
    )

    original_private = private.private_numbers()
    loaded_private_numbers = loaded_private.private_numbers()

    assert loaded_private_numbers.public_numbers.n == original_private.public_numbers.n

    assert loaded_private_numbers.d == original_private.d

    assert loaded_public.public_numbers().n == public.public_numbers().n


def test_cryptography_generate_save_load_pair_roundtrip(
    tmp_path: Path,
) -> None:
    private, public = generate_pair(
        Backend.CRYPTOGRAPHY,
    )

    assert isinstance(private, rsa.RSAPrivateKey)
    assert isinstance(public, rsa.RSAPublicKey)

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    _write_cryptography_private(private_path, private)
    _write_cryptography_public(public_path, public)

    loaded_private, loaded_public = load_pair(
        Backend.CRYPTOGRAPHY,
        private_path=private_path,
        public_path=public_path,
    )

    assert (
        loaded_private.private_numbers().public_numbers.n
        == private.private_numbers().public_numbers.n
    )

    assert loaded_public.public_numbers().n == public.public_numbers().n


def test_cryptography_generate_and_model_integration() -> None:
    private, public = generate_pair(
        Backend.CRYPTOGRAPHY,
    )

    model = CryptographyRSAKeys(
        private=private,
        public=public,
    )

    assert (
        model.private.private_numbers().public_numbers.n
        == private.private_numbers().public_numbers.n
    )

    assert model.public.public_numbers().n == public.public_numbers().n


def test_cryptography_load_dispatcher_integration(
    tmp_path: Path,
) -> None:
    private, public = generate_pair(
        Backend.CRYPTOGRAPHY,
    )

    assert isinstance(private, rsa.RSAPrivateKey)
    assert isinstance(public, rsa.RSAPublicKey)

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    _write_cryptography_private(private_path, private)
    _write_cryptography_public(public_path, public)

    loaded_private = load(
        KeyType.PRIVATE,
        Backend.CRYPTOGRAPHY,
        path=private_path,
    )

    loaded_public = load(
        KeyType.PUBLIC,
        Backend.CRYPTOGRAPHY,
        path=public_path,
    )

    assert isinstance(
        loaded_private,
        rsa.RSAPrivateKey,
    )

    assert isinstance(
        loaded_public,
        rsa.RSAPublicKey,
    )

    assert (
        loaded_private.private_numbers().public_numbers.n
        == private.private_numbers().public_numbers.n
    )

    assert loaded_public.public_numbers().n == public.public_numbers().n


def test_cryptography_encrypted_private_key_roundtrip(
    tmp_path: Path,
) -> None:
    private, public = generate_pair(
        Backend.CRYPTOGRAPHY,
    )

    assert isinstance(private, rsa.RSAPrivateKey)
    assert isinstance(public, rsa.RSAPublicKey)

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    _write_cryptography_private(
        private_path,
        private,
        password=b"secret",
    )

    _write_cryptography_public(public_path, public)

    loaded_private, loaded_public = load_pair(  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
        Backend.CRYPTOGRAPHY,
        private_path=private_path,
        public_path=public_path,
        password="secret",  # pyright: ignore[reportArgumentType]
    )  # pyright: ignore[reportCallIssue]

    assert (
        loaded_private.private_numbers().public_numbers.n  # pyright: ignore[reportUnknownMemberType]
        == private.private_numbers().public_numbers.n
    )

    assert (
        loaded_private.private_numbers().d  # pyright: ignore[reportUnknownMemberType]
        == private.private_numbers().d
    )

    assert (
        loaded_public.public_numbers().n  # pyright: ignore[reportUnknownMemberType]
        == public.public_numbers().n
    )


# =========================================================
# Cross-module behavior integration
# =========================================================


@pytest.mark.parametrize(
    "backend",
    [
        Backend.PYCRYPTODOME,
        Backend.CRYPTOGRAPHY,
    ],
)
def test_generate_public_matches_loaded_public_key(
    backend: Backend,
    tmp_path: Path,
) -> None:
    private = generate_private(backend)

    public = generate_public(private=private)

    public_path = tmp_path / "public.pem"

    if backend is Backend.PYCRYPTODOME:
        assert isinstance(public, RSA.RsaKey)

        _write_pycryptodome_public(
            public_path,
            public,
        )

        loaded_public = load_public(
            backend,
            path=public_path,
        )

        assert isinstance(loaded_public, RSA.RsaKey)

        assert loaded_public.n == public.n

    else:
        assert isinstance(public, rsa.RSAPublicKey)

        _write_cryptography_public(
            public_path,
            public,
        )

        loaded_public = load_public(
            backend,
            path=public_path,
        )

        assert isinstance(
            loaded_public,
            rsa.RSAPublicKey,
        )

        assert loaded_public.public_numbers().n == public.public_numbers().n
