import pytest
from Crypto.Hash import SHA256

from cryptiq.hashes.enums import Mode
from cryptiq.hashes.sha256 import hash, verify

# =========================================================
# hash
# =========================================================


def test_hash_object_mode_returns_sha256_object_for_bytes() -> None:
    result = hash(
        Mode.OBJECT,
        message=b"hello",
    )

    assert isinstance(result, SHA256.SHA256Hash)


def test_hash_object_mode_returns_sha256_object_for_string() -> None:
    result = hash(
        Mode.OBJECT,
        message="hello",
    )

    assert isinstance(result, SHA256.SHA256Hash)


@pytest.mark.parametrize(
    "message",
    [
        b"",
        b"hello world",
        b"binary payload",
        bytes(range(64)),
    ],
)
def test_hash_digest_mode_returns_bytes_for_bytes_input(
    message: bytes,
) -> None:
    result = hash(message=message)

    assert isinstance(result, bytes)

    # SHA256 digest size
    assert len(result) == 32


@pytest.mark.parametrize(
    "message",
    [
        "",
        "hello world",
        "🔐 secure payload",
        "こんにちは世界",
    ],
)
def test_hash_digest_mode_returns_hex_string_for_string_input(
    message: str,
) -> None:
    result = hash(message=message)

    assert isinstance(result, str)

    # SHA256 hex digest length
    assert len(result) == 64


def test_hash_same_message_produces_same_digest_for_bytes() -> None:
    first = hash(message=b"same message")
    second = hash(message=b"same message")

    assert first == second


def test_hash_same_message_produces_same_digest_for_strings() -> None:
    first = hash(message="same message")
    second = hash(message="same message")

    assert first == second


def test_hash_different_messages_produce_different_digests() -> None:
    first = hash(message="message-1")
    second = hash(message="message-2")

    assert first != second


def test_hash_object_digest_matches_digest_mode_for_bytes() -> None:
    object_hash = hash(
        Mode.OBJECT,
        message=b"payload",
    )

    digest_hash = hash(message=b"payload")

    assert isinstance(object_hash, SHA256.SHA256Hash)
    assert isinstance(digest_hash, bytes)

    assert object_hash.digest() == digest_hash


def test_hash_object_hexdigest_matches_digest_mode_for_strings() -> None:
    object_hash = hash(
        Mode.OBJECT,
        message="payload",
    )

    digest_hash = hash(message="payload")

    assert isinstance(object_hash, SHA256.SHA256Hash)
    assert isinstance(digest_hash, str)

    assert object_hash.hexdigest() == digest_hash


# =========================================================
# verify
# =========================================================


def test_verify_returns_true_for_valid_bytes_digest() -> None:
    digest = hash(message=b"payload")

    result = verify(
        b"payload",
        digest,
    )

    assert result is True


def test_verify_returns_true_for_valid_string_digest() -> None:
    digest = hash(message="payload")

    result = verify(
        "payload",
        digest,
    )

    assert result is True


def test_verify_returns_true_for_valid_sha256_object() -> None:
    object_hash = hash(
        Mode.OBJECT,
        message=b"payload",
    )

    result = verify(
        b"payload",
        object_hash,
    )

    assert result is True


def test_verify_returns_false_for_invalid_bytes_digest() -> None:
    digest = hash(message=b"payload")

    result = verify(
        b"different-payload",
        digest,
    )

    assert result is False


def test_verify_returns_false_for_invalid_string_digest() -> None:
    digest = hash(message="payload")

    result = verify(
        "different-payload",
        digest,
    )

    assert result is False


def test_verify_returns_false_for_modified_digest() -> None:
    digest = hash(message="payload")

    assert isinstance(digest, str)

    modified_digest = digest[:-1] + ("0" if digest[-1] != "0" else "1")

    result = verify(
        "payload",
        modified_digest,
    )

    assert result is False


def test_verify_returns_false_for_wrong_message_with_object_hash() -> None:
    object_hash = hash(
        Mode.OBJECT,
        message=b"payload",
    )

    result = verify(
        b"different-payload",
        object_hash,
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
        bytes(range(128)),
    ],
)
def test_bytes_roundtrip_hash_and_verify(
    message: bytes,
) -> None:
    digest = hash(message=message)

    result = verify(message, digest)

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
def test_string_roundtrip_hash_and_verify(
    message: str,
) -> None:
    digest = hash(message=message)

    result = verify(message, digest)

    assert result is True


def test_verify_accepts_sha256_object_from_hash_function() -> None:
    object_hash = hash(
        Mode.OBJECT,
        message="payload",
    )

    result = verify(
        "payload",
        object_hash,
    )

    assert result is True


def test_hash_preserves_output_type_behavior() -> None:
    bytes_digest = hash(message=b"payload")
    string_digest = hash(message="payload")

    assert isinstance(bytes_digest, bytes)
    assert isinstance(string_digest, str)


def test_hash_matches_known_sha256_digest() -> None:
    digest = hash(message="hello")

    assert digest == (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )


def test_hash_matches_known_sha256_bytes_digest() -> None:
    digest = hash(message=b"hello")

    assert digest == bytes.fromhex(
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )
