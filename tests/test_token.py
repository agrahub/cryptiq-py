from datetime import UTC, datetime, timedelta

import jwt
import pytest
from Crypto.PublicKey import RSA

from cryptiq.token import decode, encode

# =========================================================
# Fixtures
# =========================================================


@pytest.fixture(scope="module")
def private_key() -> RSA.RsaKey:
    return RSA.generate(2048)


@pytest.fixture(scope="module")
def public_key(
    private_key: RSA.RsaKey,
) -> RSA.RsaKey:
    return private_key.publickey()


# =========================================================
# encode
# =========================================================


def test_encode_returns_string(
    private_key: RSA.RsaKey,
) -> None:
    token = encode(
        payload={"sub": "123"},
        key=private_key,
    )

    assert isinstance(token, str)


def test_encode_generates_valid_jwt_structure(
    private_key: RSA.RsaKey,
) -> None:
    token = encode(
        payload={"sub": "123"},
        key=private_key,
    )

    parts = token.split(".")

    assert len(parts) == 3

    assert all(part for part in parts)


def test_encode_accepts_rsa_key_instance(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    token = encode(
        payload={"sub": "123"},
        key=private_key,
    )

    payload = decode(
        token,
        key=public_key,
    )

    assert payload["sub"] == "123"


def test_encode_accepts_exported_pem_key(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    token = encode(
        payload={"sub": "123"},
        key=private_key.export_key(),
    )

    payload = decode(
        token,
        key=public_key.export_key(),
    )

    assert payload["sub"] == "123"


def test_encode_includes_custom_headers(
    private_key: RSA.RsaKey,
) -> None:
    token = encode(
        payload={"sub": "123"},
        key=private_key,
        headers={"kid": "key-1"},
    )

    header = jwt.get_unverified_header(token)

    assert header["kid"] == "key-1"


def test_encode_supports_custom_algorithm_hs256() -> None:
    token = encode(
        payload={"sub": "123"},
        key="secret" * 6,
        algorithm="HS256",
    )

    payload = decode(
        token,
        key="secret" * 6,
        algorithms=("HS256",),
    )

    assert payload["sub"] == "123"


def test_encode_preserves_payload_values(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    original_payload = {
        "sub": "123",
        "role": "admin",
        "active": True,
    }

    token = encode(
        payload=original_payload,
        key=private_key,
    )

    decoded_payload = decode(
        token,
        key=public_key,
    )

    assert decoded_payload["sub"] == "123"
    assert decoded_payload["role"] == "admin"
    assert decoded_payload["active"] is True


# =========================================================
# decode
# =========================================================


def test_decode_returns_payload_dictionary(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    token = encode(
        payload={"sub": "123"},
        key=private_key,
    )

    payload = decode(
        token,
        key=public_key,
    )

    assert isinstance(payload, dict)


def test_decode_verifies_valid_token(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    token = encode(
        payload={"sub": "123"},
        key=private_key,
    )

    payload = decode(
        token,
        key=public_key,
    )

    assert payload["sub"] == "123"


def test_decode_raises_error_for_invalid_signature(
    private_key: RSA.RsaKey,
) -> None:
    other_private_key = RSA.generate(2048)

    other_public_key = other_private_key.publickey()

    token = encode(
        payload={"sub": "123"},
        key=private_key,
    )

    with pytest.raises(jwt.InvalidSignatureError):
        decode(
            token,
            key=other_public_key,
        )


def test_decode_raises_error_for_invalid_algorithm(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    token = encode(
        payload={"sub": "123"},
        key=private_key,
    )

    with pytest.raises(jwt.InvalidAlgorithmError):
        decode(
            token,
            key=public_key,
            algorithms=("HS256",),
        )


def test_decode_validates_audience_claim(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    token = encode(
        payload={
            "sub": "123",
            "aud": "my-api",
        },
        key=private_key,
    )

    payload = decode(
        token,
        key=public_key,
        audience="my-api",
    )

    assert payload["aud"] == "my-api"


def test_decode_raises_error_for_invalid_audience(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    token = encode(
        payload={
            "sub": "123",
            "aud": "my-api",
        },
        key=private_key,
    )

    with pytest.raises(jwt.InvalidAudienceError):
        decode(
            token,
            key=public_key,
            audience="different-api",
        )


def test_decode_validates_subject_claim(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    token = encode(
        payload={
            "sub": "user-123",
        },
        key=private_key,
    )

    payload = decode(
        token,
        key=public_key,
        subject="user-123",
    )

    assert payload["sub"] == "user-123"


def test_decode_raises_error_for_invalid_subject(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    token = encode(
        payload={
            "sub": "user-123",
        },
        key=private_key,
    )

    with pytest.raises(jwt.InvalidTokenError):
        decode(
            token,
            key=public_key,
            subject="different-user",
        )


def test_decode_validates_issuer_claim(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    token = encode(
        payload={
            "sub": "123",
            "iss": "cryptiq",
        },
        key=private_key,
    )

    payload = decode(
        token,
        key=public_key,
        issuer="cryptiq",
    )

    assert payload["iss"] == "cryptiq"


def test_decode_raises_error_for_invalid_issuer(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    token = encode(
        payload={
            "sub": "123",
            "iss": "cryptiq",
        },
        key=private_key,
    )

    with pytest.raises(jwt.InvalidIssuerError):
        decode(
            token,
            key=public_key,
            issuer="other-issuer",
        )


def test_decode_validates_expiration_claim(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    payload = {
        "sub": "123",
        "exp": datetime.now(UTC) + timedelta(minutes=5),
    }

    token = encode(
        payload=payload,
        key=private_key,
    )

    decoded_payload = decode(
        token,
        key=public_key,
    )

    assert decoded_payload["sub"] == "123"


def test_decode_raises_error_for_expired_token(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    payload = {
        "sub": "123",
        "exp": datetime.now(UTC) - timedelta(minutes=5),
    }

    token = encode(
        payload=payload,
        key=private_key,
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        decode(
            token,
            key=public_key,
        )


def test_decode_respects_leeway_for_expired_token(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    payload = {
        "sub": "123",
        "exp": datetime.now(UTC) - timedelta(seconds=1),
    }

    token = encode(
        payload=payload,
        key=private_key,
    )

    decoded_payload = decode(
        token,
        key=public_key,
        leeway=5,
    )

    assert decoded_payload["sub"] == "123"


def test_decode_accepts_string_key_for_hs256() -> None:
    token = encode(
        payload={"sub": "123"},
        key="secret" * 6,
        algorithm="HS256",
    )

    payload = decode(
        token,
        key="secret" * 6,
        algorithms=("HS256",),
    )

    assert payload["sub"] == "123"


def test_decode_raises_error_for_malformed_token(
    public_key: RSA.RsaKey,
) -> None:
    with pytest.raises(jwt.PyJWTError):
        decode(
            "invalid.token.value",
            key=public_key,
        )


# =========================================================
# Roundtrip behavior
# =========================================================


def test_encode_decode_roundtrip_with_rsa_keys(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    original_payload = {
        "sub": "123",
        "role": "admin",
        "permissions": ["read", "write"],
    }

    token = encode(
        payload=original_payload,
        key=private_key,
    )

    decoded_payload = decode(
        token,
        key=public_key,
    )

    assert decoded_payload["sub"] == original_payload["sub"]
    assert decoded_payload["role"] == original_payload["role"]
    assert decoded_payload["permissions"] == original_payload["permissions"]


def test_encode_decode_roundtrip_with_hs256() -> None:
    original_payload = {
        "sub": "123",
        "role": "admin",
    }

    token = encode(
        payload=original_payload,
        key="secret" * 6,
        algorithm="HS256",
    )

    decoded_payload = decode(
        token,
        key="secret" * 6,
        algorithms=("HS256",),
    )

    assert decoded_payload["sub"] == original_payload["sub"]
    assert decoded_payload["role"] == original_payload["role"]
