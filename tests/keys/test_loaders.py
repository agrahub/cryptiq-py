from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptiq.keys.enums import KeyType
from cryptiq.keys.loaders import (
    load,
    load_pair,
    load_private,
    load_public,
)


@pytest.fixture
def rsa_keys(tmp_path: Path) -> tuple[Path, Path]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    return private_path, public_path


def test_load_private(rsa_keys: tuple[Path, Path]) -> None:
    private_path, _ = rsa_keys

    key = load_private(private_path)

    assert isinstance(key, rsa.RSAPrivateKey)


def test_load_public(rsa_keys: tuple[Path, Path]) -> None:
    _, public_path = rsa_keys

    key = load_public(public_path)

    assert isinstance(key, rsa.RSAPublicKey)


def test_load_private_dispatch(rsa_keys: tuple[Path, Path]) -> None:
    private_path, _ = rsa_keys

    key = load(
        KeyType.PRIVATE,
        path=private_path,
    )

    assert isinstance(key, rsa.RSAPrivateKey)


def test_load_public_dispatch(rsa_keys: tuple[Path, Path]) -> None:
    _, public_path = rsa_keys

    key = load(
        KeyType.PUBLIC,
        path=public_path,
    )

    assert isinstance(key, rsa.RSAPublicKey)


def test_load_pair(rsa_keys: tuple[Path, Path]) -> None:
    private_path, public_path = rsa_keys

    private_key, public_key = load_pair(
        private_path,
        public_path,
    )

    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert isinstance(public_key, rsa.RSAPublicKey)


def test_load_private_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "missing.pem"

    with pytest.raises(FileNotFoundError):
        load_private(path)


def test_load_public_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "missing.pem"

    with pytest.raises(FileNotFoundError):
        load_public(path)


def test_load_private_invalid_pem(tmp_path: Path) -> None:
    path = tmp_path / "invalid.pem"
    path.write_text("invalid pem")

    with pytest.raises(ValueError):
        load_private(path)


def test_load_public_invalid_pem(tmp_path: Path) -> None:
    path = tmp_path / "invalid.pem"
    path.write_text("invalid pem")

    with pytest.raises(ValueError):
        load_public(path)


def test_load_private_with_password(tmp_path: Path) -> None:
    password = b"secret-password"

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )

    path = tmp_path / "encrypted.pem"
    path.write_bytes(pem)

    key = load_private(path, password)

    assert isinstance(key, rsa.RSAPrivateKey)


def test_load_private_with_string_password(tmp_path: Path) -> None:
    password = "secret-password"

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )

    path = tmp_path / "encrypted.pem"
    path.write_bytes(pem)

    key = load_private(path, password)

    assert isinstance(key, rsa.RSAPrivateKey)


def test_load_private_wrong_password(tmp_path: Path) -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"correct-password"),
    )

    path = tmp_path / "encrypted.pem"
    path.write_bytes(pem)

    with pytest.raises(ValueError):
        load_private(path, b"wrong-password")
