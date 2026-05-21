from pathlib import Path

import pytest
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptiq.enums import Backend
from cryptiq.keys.enums import KeyType
from cryptiq.keys.rsa.generators import generate_pair
from cryptiq.keys.rsa.loaders import (
    load,
    load_pair,
    load_private,
    load_public,
)

# =========================================================
# Helpers
# =========================================================


def _write_pycryptodome_private_key(
    path: Path,
    *,
    encrypted: bool = False,
    password: str = "secret",
) -> RSA.RsaKey:
    private, _ = generate_pair(Backend.PYCRYPTODOME)

    assert isinstance(private, RSA.RsaKey)

    if encrypted:
        data = private.export_key(
            passphrase=password,
            pkcs=8,
            protection="scryptAndAES128-CBC",
        )
    else:
        data = private.export_key()

    path.write_bytes(data)

    return private


def _write_pycryptodome_public_key(path: Path) -> RSA.RsaKey:
    _, public = generate_pair(Backend.PYCRYPTODOME)

    assert isinstance(public, RSA.RsaKey)

    path.write_bytes(public.export_key())

    return public


def _write_cryptography_private_key(
    path: Path,
    *,
    encrypted: bool = False,
    password: bytes = b"secret",
) -> rsa.RSAPrivateKey:
    private, _ = generate_pair(Backend.CRYPTOGRAPHY)

    assert isinstance(private, rsa.RSAPrivateKey)

    algorithm: serialization.KeySerializationEncryption

    if encrypted:
        algorithm = serialization.BestAvailableEncryption(password)
    else:
        algorithm = serialization.NoEncryption()

    data = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=algorithm,
    )

    path.write_bytes(data)

    return private


def _write_cryptography_public_key(path: Path) -> rsa.RSAPublicKey:
    _, public = generate_pair(Backend.CRYPTOGRAPHY)

    assert isinstance(public, rsa.RSAPublicKey)

    data = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    path.write_bytes(data)

    return public


# =========================================================
# load_private
# =========================================================


def test_load_private_pycryptodome_unencrypted(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private.pem"

    original = _write_pycryptodome_private_key(path)

    loaded = load_private(
        Backend.PYCRYPTODOME,
        path=path,
    )

    assert isinstance(loaded, RSA.RsaKey)

    assert loaded.has_private()

    assert loaded.n == original.n
    assert loaded.e == original.e
    assert loaded.d == original.d


def test_load_private_pycryptodome_encrypted_with_string_password(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private.pem"

    original = _write_pycryptodome_private_key(
        path,
        encrypted=True,
        password="secret",
    )

    loaded = load_private(
        Backend.PYCRYPTODOME,
        path=path,
        password="secret",
    )

    assert isinstance(loaded, RSA.RsaKey)

    assert loaded.has_private()

    assert loaded.n == original.n
    assert loaded.d == original.d


def test_load_private_pycryptodome_encrypted_with_bytes_password(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private.pem"

    _write_pycryptodome_private_key(
        path,
        encrypted=True,
        password="secret",
    )

    loaded = load_private(  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
        Backend.PYCRYPTODOME,
        path=path,
        password=b"secret",  # pyright: ignore[reportArgumentType]
    )

    assert isinstance(loaded, RSA.RsaKey)

    assert loaded.has_private()


def test_load_private_pycryptodome_invalid_password_raises_value_error(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private.pem"

    _write_pycryptodome_private_key(
        path,
        encrypted=True,
        password="correct-password",
    )

    with pytest.raises(ValueError):
        load_private(
            Backend.PYCRYPTODOME,
            path=path,
            password="wrong-password",
        )


def test_load_private_cryptography_unencrypted(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private.pem"

    original = _write_cryptography_private_key(path)

    loaded = load_private(
        Backend.CRYPTOGRAPHY,
        path=path,
    )

    assert isinstance(loaded, rsa.RSAPrivateKey)

    original_numbers = original.private_numbers()
    loaded_numbers = loaded.private_numbers()

    assert loaded_numbers.public_numbers.n == (original_numbers.public_numbers.n)

    assert loaded_numbers.d == original_numbers.d


def test_load_private_cryptography_encrypted_with_bytes_password(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private.pem"

    _write_cryptography_private_key(
        path,
        encrypted=True,
        password=b"secret",
    )

    loaded = load_private(
        Backend.CRYPTOGRAPHY,
        path=path,
        password=b"secret",
    )

    assert isinstance(loaded, rsa.RSAPrivateKey)


def test_load_private_cryptography_encrypted_with_string_password(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private.pem"

    _write_cryptography_private_key(
        path,
        encrypted=True,
        password=b"secret",
    )

    loaded = load_private(  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
        Backend.CRYPTOGRAPHY,
        path=path,
        password="secret",  # pyright: ignore[reportArgumentType]
    )

    assert isinstance(loaded, rsa.RSAPrivateKey)


def test_load_private_cryptography_invalid_password_raises_value_error(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private.pem"

    _write_cryptography_private_key(
        path,
        encrypted=True,
        password=b"correct-password",
    )

    with pytest.raises(ValueError):
        load_private(
            Backend.CRYPTOGRAPHY,
            path=path,
            password=b"wrong-password",
        )


def test_load_private_missing_file_raises_file_not_found_error() -> None:
    with pytest.raises(FileNotFoundError):
        load_private(
            Backend.PYCRYPTODOME,
            path="does-not-exist.pem",
        )


def test_load_private_rejects_public_key_for_pycryptodome(
    tmp_path: Path,
) -> None:
    path = tmp_path / "public.pem"

    public = _write_pycryptodome_public_key(path)

    assert not public.has_private()

    with pytest.raises(TypeError):
        load_private(
            Backend.PYCRYPTODOME,
            path=path,
        )


# =========================================================
# load_public
# =========================================================


def test_load_public_pycryptodome(
    tmp_path: Path,
) -> None:
    path = tmp_path / "public.pem"

    original = _write_pycryptodome_public_key(path)

    loaded = load_public(
        Backend.PYCRYPTODOME,
        path=path,
    )

    assert isinstance(loaded, RSA.RsaKey)

    assert not loaded.has_private()

    assert loaded.n == original.n
    assert loaded.e == original.e


def test_load_public_cryptography(
    tmp_path: Path,
) -> None:
    path = tmp_path / "public.pem"

    original = _write_cryptography_public_key(path)

    loaded = load_public(
        Backend.CRYPTOGRAPHY,
        path=path,
    )

    assert isinstance(loaded, rsa.RSAPublicKey)

    assert loaded.public_numbers().n == original.public_numbers().n

    assert loaded.public_numbers().e == original.public_numbers().e


def test_load_public_missing_file_raises_file_not_found_error() -> None:
    with pytest.raises(FileNotFoundError):
        load_public(
            Backend.PYCRYPTODOME,
            path="does-not-exist.pem",
        )


def test_load_public_rejects_private_key_for_pycryptodome(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private.pem"

    private = _write_pycryptodome_private_key(path)

    assert private.has_private()

    with pytest.raises(TypeError):
        load_public(
            Backend.PYCRYPTODOME,
            path=path,
        )


# =========================================================
# load
# =========================================================


def test_load_dispatches_private_key_loading(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private.pem"

    _write_pycryptodome_private_key(path)

    loaded = load(
        KeyType.PRIVATE,
        Backend.PYCRYPTODOME,
        path=path,
    )

    assert isinstance(loaded, RSA.RsaKey)

    assert loaded.has_private()


def test_load_dispatches_public_key_loading(
    tmp_path: Path,
) -> None:
    path = tmp_path / "public.pem"

    _write_pycryptodome_public_key(path)

    loaded = load(
        KeyType.PUBLIC,
        Backend.PYCRYPTODOME,
        path=path,
    )

    assert isinstance(loaded, RSA.RsaKey)

    assert not loaded.has_private()


# =========================================================
# load_pair
# =========================================================


def test_load_pair_pycryptodome(
    tmp_path: Path,
) -> None:
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    original_private = _write_pycryptodome_private_key(private_path)

    original_public = _write_pycryptodome_public_key(public_path)

    loaded_private, loaded_public = load_pair(
        Backend.PYCRYPTODOME,
        private_path=private_path,
        public_path=public_path,
    )

    assert isinstance(loaded_private, RSA.RsaKey)
    assert isinstance(loaded_public, RSA.RsaKey)

    assert loaded_private.has_private()
    assert not loaded_public.has_private()

    assert loaded_private.n == original_private.n
    assert loaded_public.n == original_public.n


def test_load_pair_cryptography(
    tmp_path: Path,
) -> None:
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    original_private = _write_cryptography_private_key(private_path)

    original_public = _write_cryptography_public_key(public_path)

    loaded_private, loaded_public = load_pair(
        Backend.CRYPTOGRAPHY,
        private_path=private_path,
        public_path=public_path,
    )

    assert isinstance(loaded_private, rsa.RSAPrivateKey)
    assert isinstance(loaded_public, rsa.RSAPublicKey)

    assert (
        loaded_private.private_numbers().public_numbers.n
        == original_private.private_numbers().public_numbers.n
    )

    assert loaded_public.public_numbers().n == original_public.public_numbers().n


def test_load_pair_with_encrypted_private_key(
    tmp_path: Path,
) -> None:
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    _write_pycryptodome_private_key(
        private_path,
        encrypted=True,
        password="secret",
    )

    _write_pycryptodome_public_key(public_path)

    private, public = load_pair(
        Backend.PYCRYPTODOME,
        private_path=private_path,
        public_path=public_path,
        password="secret",
    )

    assert isinstance(private, RSA.RsaKey)
    assert isinstance(public, RSA.RsaKey)

    assert private.has_private()
    assert not public.has_private()
