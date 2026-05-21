from pathlib import Path

import pytest
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptiq.enums import Backend
from cryptiq.keys.enums import Format, KeyType
from cryptiq.keys.rsa.generators import (
    generate_pair,
    generate_private,
    generate_public,
)
from cryptiq.keys.rsa.serializers import (
    serialize,
    serialize_pair,
    serialize_private,
    serialize_public,
)

# =========================================================
# serialize_private
# =========================================================


@pytest.mark.parametrize("format", [Format.BYTES, Format.STRING])
def test_serialize_private_cryptography_returns_expected_type(
    format: Format,
) -> None:
    private = generate_private()

    serialized = serialize_private(
        private,
        format=format,
    )

    if format is Format.BYTES:
        assert isinstance(serialized, bytes)

        assert (
            b"BEGIN ENCRYPTED PRIVATE KEY" in serialized
            or b"BEGIN PRIVATE KEY" in serialized
        )

    else:
        assert isinstance(serialized, str)

        assert (
            "BEGIN ENCRYPTED PRIVATE KEY" in serialized
            or "BEGIN PRIVATE KEY" in serialized
        )


@pytest.mark.parametrize("format", [Format.BYTES, Format.STRING])
def test_serialize_private_pycryptodome_returns_expected_type(
    format: Format,
) -> None:
    private = generate_private()

    serialized = serialize_private(
        private,
        format=format,
    )

    if format is Format.BYTES:
        assert isinstance(serialized, bytes)

        assert (
            b"BEGIN ENCRYPTED PRIVATE KEY" in serialized
            or b"BEGIN PRIVATE KEY" in serialized
        )

    else:
        assert isinstance(serialized, str)

        assert (
            "BEGIN ENCRYPTED PRIVATE KEY" in serialized
            or "BEGIN PRIVATE KEY" in serialized
        )


def test_serialize_private_cryptography_supports_password() -> None:
    private = generate_private(Backend.CRYPTOGRAPHY)

    serialized = serialize_private(
        private,
        password=b"secret",
        format=Format.BYTES,
    )

    assert isinstance(serialized, bytes)

    assert b"ENCRYPTED PRIVATE KEY" in serialized


def test_serialize_private_pycryptodome_supports_password() -> None:
    private, _ = generate_pair()

    assert isinstance(private, RSA.RsaKey)

    serialized = serialize_private(
        private,
        password="secret",
        format=Format.BYTES,
    )

    assert isinstance(serialized, bytes)

    assert b"ENCRYPTED PRIVATE KEY" in serialized


def test_serialize_private_writes_to_path(
    tmp_path: Path,
) -> None:
    private = generate_private()

    path = tmp_path / "private.pem"

    result = serialize_private(
        private,
        format=None,
        path=path,
    )

    assert result is None

    assert path.exists()

    content = path.read_bytes()

    assert b"PRIVATE KEY" in content


# =========================================================
# serialize_public
# =========================================================


@pytest.mark.parametrize("format", [Format.BYTES, Format.STRING])
def test_serialize_public_cryptography_returns_expected_type(
    format: Format,
) -> None:
    private = generate_private(Backend.CRYPTOGRAPHY)

    public = generate_public(private=private)

    serialized = serialize_public(
        public,
        format=format,
    )

    if format is Format.BYTES:
        assert isinstance(serialized, bytes)

        assert b"BEGIN PUBLIC KEY" in serialized

    else:
        assert isinstance(serialized, str)

        assert "BEGIN PUBLIC KEY" in serialized


@pytest.mark.parametrize("format", [Format.BYTES, Format.STRING])
def test_serialize_public_pycryptodome_returns_expected_type(
    format: Format,
) -> None:
    _, public = generate_pair()

    assert isinstance(public, RSA.RsaKey)

    serialized = serialize_public(
        public,
        format=format,
    )

    if format is Format.BYTES:
        assert isinstance(serialized, bytes)

        assert b"BEGIN PUBLIC KEY" in serialized

    else:
        assert isinstance(serialized, str)

        assert "BEGIN PUBLIC KEY" in serialized


def test_serialize_public_writes_to_path(
    tmp_path: Path,
) -> None:
    private = generate_private()

    public = generate_public(private=private)

    path = tmp_path / "public.pem"

    result = serialize_public(
        public,
        format=None,
        path=path,
    )

    assert result is None

    assert path.exists()

    content = path.read_bytes()

    assert b"PUBLIC KEY" in content


# =========================================================
# serialize dispatcher
# =========================================================


def test_serialize_dispatches_private_key_serialization() -> None:
    private = generate_private()

    serialized = serialize(
        KeyType.PRIVATE,
        private,
        format=Format.BYTES,
    )

    assert isinstance(serialized, bytes)

    assert b"PRIVATE KEY" in serialized


def test_serialize_dispatches_public_key_serialization() -> None:
    private = generate_private()

    public = generate_public(private=private)

    serialized = serialize(
        KeyType.PUBLIC,
        public,
        format=Format.BYTES,
    )

    assert isinstance(serialized, bytes)

    assert b"PUBLIC KEY" in serialized


def test_serialize_private_dispatcher_supports_path(
    tmp_path: Path,
) -> None:
    private = generate_private()

    path = tmp_path / "private.pem"

    result = serialize(
        KeyType.PRIVATE,
        private,
        format=None,
        path=path,
    )

    assert result is None

    assert path.exists()


def test_serialize_public_dispatcher_supports_path(
    tmp_path: Path,
) -> None:
    private = generate_private()

    public = generate_public(private=private)

    path = tmp_path / "public.pem"

    result = serialize(
        KeyType.PUBLIC,
        public,
        format=None,
        path=path,
    )

    assert result is None

    assert path.exists()


# =========================================================
# serialize_pair
# =========================================================


@pytest.mark.parametrize("format", [Format.BYTES, Format.STRING])
def test_serialize_pair_cryptography_returns_expected_types(
    format: Format,
) -> None:
    keys = generate_pair()

    serialized_private, serialized_public = serialize_pair(
        keys,
        format=format,
    )

    if format is Format.BYTES:
        assert isinstance(serialized_private, bytes)
        assert isinstance(serialized_public, bytes)

        assert b"PRIVATE KEY" in serialized_private
        assert b"PUBLIC KEY" in serialized_public

    else:
        assert isinstance(serialized_private, str)
        assert isinstance(serialized_public, str)

        assert "PRIVATE KEY" in serialized_private
        assert "PUBLIC KEY" in serialized_public


def test_serialize_pair_pycryptodome_returns_expected_types() -> None:
    keys = generate_pair()

    serialized_private, serialized_public = serialize_pair(
        keys,
        format=Format.BYTES,
    )

    assert isinstance(serialized_private, bytes)
    assert isinstance(serialized_public, bytes)

    assert b"PRIVATE KEY" in serialized_private
    assert b"PUBLIC KEY" in serialized_public


def test_serialize_pair_supports_password() -> None:
    keys = generate_pair()

    serialized_private, serialized_public = serialize_pair(
        keys,
        password="secret",
        format=Format.BYTES,
    )

    assert isinstance(serialized_private, bytes)
    assert isinstance(serialized_public, bytes)

    assert b"ENCRYPTED PRIVATE KEY" in serialized_private

    assert b"PUBLIC KEY" in serialized_public


def test_serialize_pair_writes_both_keys_to_paths(
    tmp_path: Path,
) -> None:
    keys = generate_pair()

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    result = serialize_pair(
        keys,
        format=None,
        private_path=private_path,
        public_path=public_path,
    )

    assert result is None

    assert private_path.exists()
    assert public_path.exists()

    assert b"PRIVATE KEY" in private_path.read_bytes()

    assert b"PUBLIC KEY" in public_path.read_bytes()


# =========================================================
# Serialization interoperability
# =========================================================


def test_cryptography_private_serialization_can_be_loaded() -> None:
    private = generate_private(Backend.CRYPTOGRAPHY)

    serialized = serialize_private(
        private,
        format=Format.BYTES,
    )

    assert isinstance(serialized, bytes)

    loaded = serialization.load_pem_private_key(
        serialized,
        password=None,
    )

    assert isinstance(loaded, rsa.RSAPrivateKey)

    assert (
        loaded.private_numbers().public_numbers.n
        == private.private_numbers().public_numbers.n
    )


def test_cryptography_public_serialization_can_be_loaded() -> None:
    private = generate_private(Backend.CRYPTOGRAPHY)

    public = generate_public(private=private)

    serialized = serialize_public(
        public,
        format=Format.BYTES,
    )

    assert isinstance(serialized, bytes)

    loaded = serialization.load_pem_public_key(
        serialized,
    )

    assert isinstance(loaded, rsa.RSAPublicKey)

    assert loaded.public_numbers().n == public.public_numbers().n


def test_pycryptodome_private_serialization_can_be_loaded() -> None:
    private, _ = generate_pair()

    assert isinstance(private, RSA.RsaKey)

    serialized = serialize_private(
        private,
        format=Format.BYTES,
    )

    assert isinstance(serialized, bytes)

    loaded = RSA.import_key(serialized)

    assert loaded.has_private()

    assert loaded.n == private.n


def test_pycryptodome_public_serialization_can_be_loaded() -> None:
    _, public = generate_pair()

    assert isinstance(public, RSA.RsaKey)

    serialized = serialize_public(
        public,
        format=Format.BYTES,
    )

    assert isinstance(serialized, bytes)

    loaded = RSA.import_key(serialized)

    assert not loaded.has_private()

    assert loaded.n == public.n
