import bcrypt
import pytest

from cryptiq.hashes.bcrypt import hash, verify

# =========================================================
# hash
# =========================================================


@pytest.mark.parametrize(
    "password",
    [
        b"",
        b"password",
        b"super-secret-password",
        bytes(range(32)),
    ],
)
def test_hash_bytes_returns_bytes(
    password: bytes,
) -> None:
    password_hash = hash(password)

    assert isinstance(password_hash, bytes)


@pytest.mark.parametrize(
    "password",
    [
        "",
        "password",
        "super-secret-password",
        "🔐 unicode-password",
    ],
)
def test_hash_string_returns_string(
    password: str,
) -> None:
    password_hash = hash(password)

    assert isinstance(password_hash, str)


def test_hash_generates_valid_bcrypt_hash_for_bytes() -> None:
    password = b"my-password"

    password_hash = hash(password)

    assert bcrypt.checkpw(password, password_hash)


def test_hash_generates_valid_bcrypt_hash_for_string() -> None:
    password = "my-password"

    password_hash = hash(password)

    assert bcrypt.checkpw(
        password.encode(),
        password_hash.encode(),
    )


def test_hash_generates_unique_hashes_for_same_password() -> None:
    password = "same-password"

    first_hash = hash(password)
    second_hash = hash(password)

    assert first_hash != second_hash


def test_hash_contains_bcrypt_prefix_for_bytes() -> None:
    password_hash = hash(b"password")

    assert password_hash.startswith(b"$2")


def test_hash_contains_bcrypt_prefix_for_string() -> None:
    password_hash = hash("password")

    assert password_hash.startswith("$2")


# =========================================================
# verify
# =========================================================


def test_verify_returns_true_for_correct_bytes_password() -> None:
    password = b"correct-password"

    password_hash = hash(password)

    assert verify(password, password_hash) is True


def test_verify_returns_true_for_correct_string_password() -> None:
    password = "correct-password"

    password_hash = hash(password)

    assert verify(password, password_hash) is True


def test_verify_returns_false_for_incorrect_bytes_password() -> None:
    password_hash = hash(b"correct-password")

    result = verify(
        b"wrong-password",
        password_hash,
    )

    assert result is False


def test_verify_returns_false_for_incorrect_string_password() -> None:
    password_hash = hash("correct-password")

    result = verify(
        "wrong-password",
        password_hash,
    )

    assert result is False


@pytest.mark.parametrize(
    "invalid_hash",
    [
        b"",
        b"invalid",
        b"not-a-bcrypt-hash",
    ],
)
def test_verify_invalid_bytes_hash_raises_value_error(
    invalid_hash: bytes,
) -> None:
    with pytest.raises(ValueError):
        verify(
            b"password",
            invalid_hash,
        )


@pytest.mark.parametrize(
    "invalid_hash",
    [
        "",
        "invalid",
        "not-a-bcrypt-hash",
    ],
)
def test_verify_invalid_string_hash_raises_value_error(
    invalid_hash: str,
) -> None:
    with pytest.raises(ValueError):
        verify(
            "password",
            invalid_hash,
        )


# =========================================================
# Roundtrip behavior
# =========================================================


@pytest.mark.parametrize(
    "password",
    [
        b"",
        b"simple-password",
        bytes(range(64)),
    ],
)
def test_bytes_hash_and_verify_roundtrip(
    password: bytes,
) -> None:
    password_hash = hash(password)

    result = verify(password, password_hash)

    assert result is True


@pytest.mark.parametrize(
    "password",
    [
        "",
        "simple-password",
        "こんにちは",
        "🔐 secure-password",
    ],
)
def test_string_hash_and_verify_roundtrip(
    password: str,
) -> None:
    password_hash = hash(password)

    result = verify(password, password_hash)

    assert result is True


def test_verify_rejects_hash_from_different_password() -> None:
    first_hash = hash("first-password")

    result = verify(
        "second-password",
        first_hash,
    )

    assert result is False


def test_hash_preserves_input_type_behavior() -> None:
    string_hash = hash("password")
    bytes_hash = hash(b"password")

    assert isinstance(string_hash, str)
    assert isinstance(bytes_hash, bytes)


def test_verify_accepts_matching_string_types() -> None:
    password = "typed-password"

    password_hash = hash(password)

    result = verify(password, password_hash)

    assert result is True


def test_verify_accepts_matching_bytes_types() -> None:
    password = b"typed-password"

    password_hash = hash(password)

    result = verify(password, password_hash)

    assert result is True
