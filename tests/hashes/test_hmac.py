import pytest
from Crypto.Hash import HMAC

from cryptiq.hashes.enums import Mode
from cryptiq.hashes.hmac import hash, verify

# =========================================================
# hash
# =========================================================


def test_hash_object_mode_returns_hmac_object_for_bytes() -> None:
    result = hash(
        Mode.OBJECT,
        key=b"secret",
        message=b"hello",
    )

    assert isinstance(result, HMAC.HMAC)


def test_hash_object_mode_returns_hmac_object_for_string() -> None:
    result = hash(
        Mode.OBJECT,
        key="secret",
        message="hello",
    )

    assert isinstance(result, HMAC.HMAC)


@pytest.mark.parametrize(
    ("key", "message"),
    [
        (b"secret", b"hello"),
        (b"key", b"payload"),
        (b"", b""),
    ],
)
def test_hash_digest_mode_returns_bytes_for_bytes_input(
    key: bytes,
    message: bytes,
) -> None:
    result = hash(
        Mode.DIGEST,
        key=key,
        message=message,
    )

    assert isinstance(result, bytes)

    # SHA256 digest size
    assert len(result) == 32


@pytest.mark.parametrize(
    ("key", "message"),
    [
        ("secret", "hello"),
        ("key", "payload"),
        ("", ""),
        ("🔐", "秘密"),
    ],
)
def test_hash_digest_mode_returns_hex_string_for_string_input(
    key: str,
    message: str,
) -> None:
    result = hash(
        Mode.DIGEST,
        key=key,
        message=message,
    )

    assert isinstance(result, str)

    # SHA256 hex digest length
    assert len(result) == 64


def test_hash_same_inputs_produce_same_digest_for_bytes() -> None:
    first = hash(
        key=b"secret",
        message=b"message",
    )

    second = hash(
        key=b"secret",
        message=b"message",
    )

    assert first == second


def test_hash_same_inputs_produce_same_digest_for_strings() -> None:
    first = hash(
        key="secret",
        message="message",
    )

    second = hash(
        key="secret",
        message="message",
    )

    assert first == second


def test_hash_different_keys_produce_different_digests() -> None:
    first = hash(
        key="secret-1",
        message="message",
    )

    second = hash(
        key="secret-2",
        message="message",
    )

    assert first != second


def test_hash_different_messages_produce_different_digests() -> None:
    first = hash(
        key="secret",
        message="message-1",
    )

    second = hash(
        key="secret",
        message="message-2",
    )

    assert first != second


def test_hash_object_digest_matches_digest_mode_for_bytes() -> None:
    object_hash = hash(
        Mode.OBJECT,
        key=b"secret",
        message=b"payload",
    )

    digest_hash = hash(
        Mode.DIGEST,
        key=b"secret",
        message=b"payload",
    )

    assert isinstance(object_hash, HMAC.HMAC)
    assert isinstance(digest_hash, bytes)

    assert object_hash.digest() == digest_hash


def test_hash_object_hexdigest_matches_digest_mode_for_strings() -> None:
    object_hash = hash(
        Mode.OBJECT,
        key="secret",
        message="payload",
    )

    digest_hash = hash(
        Mode.DIGEST,
        key="secret",
        message="payload",
    )

    assert isinstance(object_hash, HMAC.HMAC)
    assert isinstance(digest_hash, str)

    assert object_hash.hexdigest() == digest_hash


# =========================================================
# verify
# =========================================================


def test_verify_returns_true_for_valid_bytes_digest() -> None:
    digest = hash(
        key=b"secret",
        message=b"payload",
    )

    result = verify(
        b"secret",
        b"payload",
        digest,
    )

    assert result is True


def test_verify_returns_true_for_valid_string_digest() -> None:
    digest = hash(
        key="secret",
        message="payload",
    )

    result = verify(
        "secret",
        "payload",
        digest,
    )

    assert result is True


def test_verify_returns_true_for_valid_hmac_object() -> None:
    object_hash = hash(
        Mode.OBJECT,
        key=b"secret",
        message=b"payload",
    )

    result = verify(
        b"secret",
        b"payload",
        object_hash,
    )

    assert result is True


def test_verify_returns_false_for_invalid_bytes_digest() -> None:
    digest = hash(
        key=b"secret",
        message=b"payload",
    )

    result = verify(
        b"wrong-secret",
        b"payload",
        digest,
    )

    assert result is False


def test_verify_returns_false_for_invalid_string_digest() -> None:
    digest = hash(
        key="secret",
        message="payload",
    )

    result = verify(
        "wrong-secret",
        "payload",
        digest,
    )

    assert result is False


def test_verify_returns_false_for_wrong_message() -> None:
    digest = hash(
        key="secret",
        message="payload",
    )

    result = verify(
        "secret",
        "different-payload",
        digest,
    )

    assert result is False


def test_verify_returns_false_for_modified_digest() -> None:
    digest = hash(
        key="secret",
        message="payload",
    )

    assert isinstance(digest, str)

    modified_digest = digest[:-1] + ("0" if digest[-1] != "0" else "1")

    result = verify(
        "secret",
        "payload",
        modified_digest,
    )

    assert result is False


# =========================================================
# Roundtrip behavior
# =========================================================


@pytest.mark.parametrize(
    ("key", "message"),
    [
        (b"", b""),
        (b"secret", b"payload"),
        (bytes(range(32)), bytes(range(64))),
    ],
)
def test_bytes_roundtrip_hash_and_verify(
    key: bytes,
    message: bytes,
) -> None:
    digest = hash(
        key=key,
        message=message,
    )

    result = verify(
        key,
        message,
        digest,
    )

    assert result is True


@pytest.mark.parametrize(
    ("key", "message"),
    [
        ("", ""),
        ("secret", "payload"),
        ("🔐", "秘密"),
    ],
)
def test_string_roundtrip_hash_and_verify(
    key: str,
    message: str,
) -> None:
    digest = hash(
        key=key,
        message=message,
    )

    result = verify(
        key,
        message,
        digest,
    )

    assert result is True


def test_verify_accepts_hmac_object_from_hash_function() -> None:
    object_hash = hash(
        Mode.OBJECT,
        key="secret",
        message="payload",
    )

    result = verify(  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
        "secret",
        "payload",
        object_hash,  # pyright: ignore[reportArgumentType]
    )

    assert result is True


def test_hash_preserves_output_type_behavior() -> None:
    bytes_digest = hash(
        key=b"secret",
        message=b"payload",
    )

    string_digest = hash(
        key="secret",
        message="payload",
    )

    assert isinstance(bytes_digest, bytes)
    assert isinstance(string_digest, str)
