from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptiq.enums import Backend
from cryptiq.keys.enums import Format
from cryptiq.keys.rsa.models import (
    CryptographyRSAKeys,
    PycryptodomeRSAKeys,
    RSAKeys,
)

# =========================================================
# Class configuration
# =========================================================


def test_cryptography_rsa_keys_backend_is_correct() -> None:
    assert CryptographyRSAKeys.backend is Backend.CRYPTOGRAPHY


def test_pycryptodome_rsa_keys_backend_is_correct() -> None:
    assert PycryptodomeRSAKeys.backend is Backend.PYCRYPTODOME


# =========================================================
# generate
# =========================================================


def test_cryptography_rsa_keys_generate_returns_expected_types() -> None:
    keys = CryptographyRSAKeys.generate(size=2048)

    assert isinstance(keys, CryptographyRSAKeys)
    assert isinstance(keys.private, rsa.RSAPrivateKey)
    assert isinstance(keys.public, rsa.RSAPublicKey)

    assert keys.private.key_size == 2048


def test_pycryptodome_rsa_keys_generate_returns_expected_types() -> None:
    keys = PycryptodomeRSAKeys.generate(size=2048)

    assert isinstance(keys, PycryptodomeRSAKeys)
    assert isinstance(keys.private, RSA.RsaKey)
    assert isinstance(keys.public, RSA.RsaKey)

    assert keys.private.has_private()
    assert not keys.public.has_private()

    assert keys.private.size_in_bits() == 2048
    assert keys.public.size_in_bits() == 2048


def test_generate_produces_unique_key_pairs() -> None:
    first = PycryptodomeRSAKeys.generate()
    second = PycryptodomeRSAKeys.generate()

    assert first.private.n != second.private.n
    assert first.public.n != second.public.n


# =========================================================
# Model validation
# =========================================================


def test_cryptography_model_accepts_valid_keys() -> None:
    generated = CryptographyRSAKeys.generate()

    model = CryptographyRSAKeys(
        private=generated.private,
        public=generated.public,
    )

    assert model.private is generated.private
    assert model.public is generated.public


def test_pycryptodome_model_accepts_valid_keys() -> None:
    generated = PycryptodomeRSAKeys.generate()

    model = PycryptodomeRSAKeys(
        private=generated.private,
        public=generated.public,
    )

    assert model.private is generated.private
    assert model.public is generated.public


# =========================================================
# serialize (NEW)
# =========================================================


def test_cryptography_model_serialize_bytes() -> None:
    keys = CryptographyRSAKeys.generate()

    result = keys.serialize(format=Format.BYTES)

    assert isinstance(result, tuple)
    private, public = result

    assert isinstance(private, bytes)
    assert isinstance(public, bytes)


def test_cryptography_model_serialize_string() -> None:
    keys = CryptographyRSAKeys.generate()

    result = keys.serialize(format=Format.STRING)

    assert isinstance(result, tuple)
    private, public = result

    assert isinstance(private, str)
    assert isinstance(public, str)


def test_pycryptodome_model_serialize_bytes() -> None:
    keys = PycryptodomeRSAKeys.generate()

    result = keys.serialize(format=Format.BYTES)

    assert isinstance(result, tuple)
    private, public = result

    assert isinstance(private, bytes)
    assert isinstance(public, bytes)


def test_pycryptodome_model_serialize_string() -> None:
    keys = PycryptodomeRSAKeys.generate()

    result = keys.serialize(format=Format.STRING)

    assert isinstance(result, tuple)
    private, public = result

    assert isinstance(private, str)
    assert isinstance(public, str)


def test_serialize_returns_none_when_format_is_none() -> None:
    keys = PycryptodomeRSAKeys.generate()

    result = keys.serialize()

    assert result is None


# =========================================================
# password behavior (light integration check)
# =========================================================


def test_serialize_accepts_password_both_backends() -> None:
    crypto_keys = CryptographyRSAKeys.generate()
    pycrypto_keys = PycryptodomeRSAKeys.generate()

    crypto_result = crypto_keys.serialize(password=b"secret", format=Format.BYTES)
    pycrypto_result = pycrypto_keys.serialize(password="secret", format=Format.BYTES)

    assert isinstance(crypto_result, tuple)
    assert isinstance(pycrypto_result, tuple)


# =========================================================
# Field metadata
# =========================================================


def test_private_field_has_description_metadata() -> None:
    field = RSAKeys.model_fields["private"]

    assert field.description == "The RSA private key in PEM format."


def test_public_field_has_description_metadata() -> None:
    field = RSAKeys.model_fields["public"]

    assert field.description == "The RSA public key in PEM format."


# =========================================================
# Generic inheritance
# =========================================================


def test_rsa_keys_is_generic_model() -> None:
    assert issubclass(RSAKeys, object)
    assert hasattr(RSAKeys, "__parameters__")
