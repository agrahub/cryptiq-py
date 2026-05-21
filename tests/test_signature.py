from base64 import b64decode

import pytest
from Crypto.PublicKey import RSA

from cryptiq.signature import sign, verify

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
# sign
# =========================================================


def test_sign_returns_bytes_for_bytes_message(
    private_key: RSA.RsaKey,
) -> None:
    signature = sign(
        b"hello world",
        private_key,
    )

    assert isinstance(signature, bytes)


def test_sign_returns_string_for_string_message(
    private_key: RSA.RsaKey,
) -> None:
    signature = sign(
        "hello world",
        private_key,
    )

    assert isinstance(signature, str)


def test_sign_returns_base64_encoded_bytes_signature(
    private_key: RSA.RsaKey,
) -> None:
    signature = sign(
        b"hello world",
        private_key,
    )

    decoded = b64decode(signature)

    assert isinstance(decoded, bytes)
    assert len(decoded) > 0


def test_sign_returns_base64_encoded_string_signature(
    private_key: RSA.RsaKey,
) -> None:
    signature = sign(
        "hello world",
        private_key,
    )

    decoded = b64decode(signature.encode())

    assert isinstance(decoded, bytes)
    assert len(decoded) > 0


def test_sign_same_message_produces_same_signature(
    private_key: RSA.RsaKey,
) -> None:
    first = sign(
        "same message",
        private_key,
    )

    second = sign(
        "same message",
        private_key,
    )

    assert first == second


def test_sign_different_messages_produce_different_signatures(
    private_key: RSA.RsaKey,
) -> None:
    first = sign(
        "message-1",
        private_key,
    )

    second = sign(
        "message-2",
        private_key,
    )

    assert first != second


def test_sign_empty_bytes_message(
    private_key: RSA.RsaKey,
) -> None:
    signature = sign(
        b"",
        private_key,
    )

    assert isinstance(signature, bytes)

    assert len(signature) > 0


def test_sign_empty_string_message(
    private_key: RSA.RsaKey,
) -> None:
    signature = sign(
        "",
        private_key,
    )

    assert isinstance(signature, str)

    assert len(signature) > 0


def test_sign_unicode_message(
    private_key: RSA.RsaKey,
) -> None:
    signature = sign(
        "🔐 secure message",
        private_key,
    )

    assert isinstance(signature, str)

    assert len(signature) > 0


# =========================================================
# verify
# =========================================================


def test_verify_returns_true_for_valid_bytes_signature(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    message = b"hello world"

    signature = sign(
        message,
        private_key,
    )

    result = verify(
        public_key,
        message,
        signature,
    )

    assert result is True


def test_verify_returns_true_for_valid_string_signature(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    message = "hello world"

    signature = sign(
        message,
        private_key,
    )

    result = verify(
        public_key,
        message,
        signature,
    )

    assert result is True


def test_verify_returns_false_for_modified_message(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    signature = sign(
        "original message",
        private_key,
    )

    result = verify(
        public_key,
        "modified message",
        signature,
    )

    assert result is False


def test_verify_returns_false_for_modified_bytes_message(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    signature = sign(
        b"original message",
        private_key,
    )

    result = verify(
        public_key,
        b"modified message",
        signature,
    )

    assert result is False


def test_verify_returns_false_for_modified_signature(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    signature = sign(
        "hello world",
        private_key,
    )

    assert isinstance(signature, str)

    modified_signature = signature[:-1] + ("A" if signature[-1] != "A" else "B")

    result = verify(
        public_key,
        "hello world",
        modified_signature,
    )

    assert result is False


def test_verify_returns_false_for_modified_bytes_signature(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    signature = sign(
        b"hello world",
        private_key,
    )

    assert isinstance(signature, bytes)

    modified_signature = signature[:-1] + (b"A" if signature[-1:] != b"A" else b"B")

    result = verify(
        public_key,
        b"hello world",
        modified_signature,
    )

    assert result is False


def test_verify_returns_false_with_different_public_key() -> None:
    private_key = RSA.generate(2048)

    other_private_key = RSA.generate(2048)

    other_public_key = other_private_key.publickey()

    signature = sign(
        "hello world",
        private_key,
    )

    result = verify(
        other_public_key,
        "hello world",
        signature,
    )

    assert result is False


def test_verify_returns_false_for_invalid_base64_signature(
    public_key: RSA.RsaKey,
) -> None:
    result = verify(
        public_key,
        "hello world",
        "!!!invalid-base64!!!",
    )

    assert result is False


# =========================================================
# Roundtrip behavior
# =========================================================


@pytest.mark.parametrize(
    "message",
    [
        b"",
        b"simple payload",
        bytes(range(64)),
    ],
)
def test_bytes_roundtrip_sign_and_verify(
    message: bytes,
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    signature = sign(
        message,
        private_key,
    )

    result = verify(
        public_key,
        message,
        signature,
    )

    assert result is True


@pytest.mark.parametrize(
    "message",
    [
        "",
        "simple payload",
        "こんにちは",
        "🔐 secure payload",
    ],
)
def test_string_roundtrip_sign_and_verify(
    message: str,
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    signature = sign(
        message,
        private_key,
    )

    result = verify(
        public_key,
        message,
        signature,
    )

    assert result is True


def test_sign_preserves_output_type_behavior(
    private_key: RSA.RsaKey,
) -> None:
    bytes_signature = sign(
        b"payload",
        private_key,
    )

    string_signature = sign(
        "payload",
        private_key,
    )

    assert isinstance(bytes_signature, bytes)
    assert isinstance(string_signature, str)


def test_verify_returns_boolean(
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
) -> None:
    signature = sign(
        "payload",
        private_key,
    )

    result = verify(
        public_key,
        "payload",
        signature,
    )

    assert isinstance(result, bool)
