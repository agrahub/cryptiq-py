import pytest
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptiq.enums import Backend
from cryptiq.keys.rsa.generators import (
    generate_pair,
    generate_private,
    generate_public,
)

# =========================================================
# generate_private
# =========================================================


@pytest.mark.parametrize("size", [1024, 2048, 3072, 4096])
def test_generate_private_pycryptodome_returns_rsa_key(size: int) -> None:
    private = generate_private(
        Backend.PYCRYPTODOME,
        size=size,
    )

    assert isinstance(private, RSA.RsaKey)
    assert private.has_private()

    # Validate modulus size
    assert private.size_in_bits() == size

    # Validate exponent
    assert private.e == 65537


@pytest.mark.parametrize("size", [1024, 2048, 3072, 4096])
def test_generate_private_cryptography_returns_private_key(
    size: int,
) -> None:
    private = generate_private(
        Backend.CRYPTOGRAPHY,
        size=size,
    )

    assert isinstance(private, rsa.RSAPrivateKey)

    numbers = private.private_numbers()

    # Validate modulus size
    assert private.key_size == size

    # Validate exponent
    assert numbers.public_numbers.e == 65537


def test_generate_private_uses_pycryptodome_as_default_backend() -> None:
    private = generate_private()

    assert isinstance(private, RSA.RsaKey)
    assert private.has_private()


@pytest.mark.parametrize("invalid_size", [0, 1, 511, 513, -2048])
def test_generate_private_invalid_size_raises_value_error(
    invalid_size: int,
) -> None:
    with pytest.raises(ValueError):
        generate_private(
            Backend.PYCRYPTODOME,
            size=invalid_size,
        )


# =========================================================
# generate_public
# =========================================================


def test_generate_public_from_pycryptodome_private_key() -> None:
    private = generate_private(Backend.PYCRYPTODOME)

    public = generate_public(private=private)

    assert isinstance(public, RSA.RsaKey)

    # Public key should not contain private components
    assert not public.has_private()

    # Public numbers should match
    assert public.n == private.n
    assert public.e == private.e


def test_generate_public_from_cryptography_private_key() -> None:
    private = generate_private(Backend.CRYPTOGRAPHY)

    public = generate_public(private=private)

    assert isinstance(public, rsa.RSAPublicKey)

    private_numbers = private.private_numbers()
    public_numbers = public.public_numbers()

    assert public_numbers.n == private_numbers.public_numbers.n

    assert public_numbers.e == private_numbers.public_numbers.e


# =========================================================
# generate_pair
# =========================================================


@pytest.mark.parametrize(
    ("backend", "private_type", "public_type"),
    [
        (
            Backend.PYCRYPTODOME,
            RSA.RsaKey,
            RSA.RsaKey,
        ),
        (
            Backend.CRYPTOGRAPHY,
            rsa.RSAPrivateKey,
            rsa.RSAPublicKey,
        ),
    ],
)
def test_generate_pair_returns_expected_types(
    backend: Backend,
    private_type: type,
    public_type: type,
) -> None:
    private, public = generate_pair(backend)

    assert isinstance(private, private_type)
    assert isinstance(public, public_type)


@pytest.mark.parametrize("size", [1024, 2048])
def test_generate_pair_pycryptodome_keys_match(size: int) -> None:
    private, public = generate_pair(
        Backend.PYCRYPTODOME,
        size=size,
    )

    assert isinstance(private, RSA.RsaKey)
    assert isinstance(public, RSA.RsaKey)

    assert private.has_private()
    assert not public.has_private()

    assert private.n == public.n
    assert private.e == public.e

    assert private.size_in_bits() == size
    assert public.size_in_bits() == size


@pytest.mark.parametrize("size", [1024, 2048])
def test_generate_pair_cryptography_keys_match(
    size: int,
) -> None:
    private, public = generate_pair(
        Backend.CRYPTOGRAPHY,
        size=size,
    )

    assert isinstance(private, rsa.RSAPrivateKey)
    assert isinstance(public, rsa.RSAPublicKey)

    private_numbers = private.private_numbers()
    public_numbers = public.public_numbers()

    assert private_numbers.public_numbers.n == public_numbers.n

    assert private_numbers.public_numbers.e == public_numbers.e

    assert private.key_size == size


def test_generate_pair_uses_pycryptodome_as_default_backend() -> None:
    private, public = generate_pair()

    assert isinstance(private, RSA.RsaKey)
    assert isinstance(public, RSA.RsaKey)


# =========================================================
# Behavioral consistency
# =========================================================


def test_generate_public_matches_generate_pair_public_pycryptodome() -> None:
    private = generate_private(Backend.PYCRYPTODOME)

    derived_public = generate_public(private=private)

    pair_private, pair_public = generate_pair(Backend.PYCRYPTODOME)

    assert isinstance(derived_public, RSA.RsaKey)
    assert isinstance(pair_public, RSA.RsaKey)

    # Ensure independently generated keys differ
    assert private.n != pair_private.n

    # Ensure derived key matches original private key
    assert derived_public.n == private.n
    assert derived_public.e == private.e


def test_generate_public_matches_generate_pair_public_cryptography() -> None:
    private = generate_private(Backend.CRYPTOGRAPHY)

    derived_public = generate_public(private=private)

    pair_private, pair_public = generate_pair(Backend.CRYPTOGRAPHY)

    assert isinstance(derived_public, rsa.RSAPublicKey)
    assert isinstance(pair_public, rsa.RSAPublicKey)

    derived_numbers = derived_public.public_numbers()

    private_numbers = private.private_numbers()

    assert derived_numbers.n == private_numbers.public_numbers.n

    assert derived_numbers.e == private_numbers.public_numbers.e

    # Independently generated pair should differ
    assert (
        pair_private.private_numbers().public_numbers.n
        != private_numbers.public_numbers.n
    )
