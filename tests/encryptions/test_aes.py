from base64 import b64decode

import pytest

from cryptiq.encryptions.aes import decrypt, encrypt

# =========================================================
# encrypt
# =========================================================


@pytest.mark.parametrize(
    "plaintext",
    [
        b"",
        b"hello world",
        b"\x00\x01\x02\x03",
        bytes(range(256)),
    ],
)
def test_encrypt_bytes_returns_base64_encoded_bytes_tuple(
    plaintext: bytes,
) -> None:
    key, iv, ciphertext = encrypt(plaintext)

    assert isinstance(key, bytes)
    assert isinstance(iv, bytes)
    assert isinstance(ciphertext, bytes)

    decoded_key = b64decode(key)
    decoded_iv = b64decode(iv)
    decoded_ciphertext = b64decode(ciphertext)

    assert len(decoded_key) == 32
    assert len(decoded_iv) == 16

    assert isinstance(decoded_ciphertext, bytes)


@pytest.mark.parametrize(
    "plaintext",
    [
        "",
        "hello world",
        "こんにちは世界",
        "🔐 encrypted message",
    ],
)
def test_encrypt_string_returns_base64_encoded_string_tuple(
    plaintext: str,
) -> None:
    key, iv, ciphertext = encrypt(plaintext)

    assert isinstance(key, str)
    assert isinstance(iv, str)
    assert isinstance(ciphertext, str)

    decoded_key = b64decode(key)
    decoded_iv = b64decode(iv)
    decoded_ciphertext = b64decode(ciphertext)

    assert len(decoded_key) == 32
    assert len(decoded_iv) == 16

    assert isinstance(decoded_ciphertext, bytes)


def test_encrypt_generates_unique_keys_and_iv() -> None:
    plaintext = "same plaintext"

    first = encrypt(plaintext)
    second = encrypt(plaintext)

    first_key, first_iv, first_ciphertext = first
    second_key, second_iv, second_ciphertext = second

    assert first_key != second_key
    assert first_iv != second_iv

    # Ciphertexts should also differ because IV/key differ
    assert first_ciphertext != second_ciphertext


def test_encrypt_same_input_can_be_decrypted_correctly() -> None:
    plaintext = "confidential message"

    key, iv, ciphertext = encrypt(plaintext)

    decrypted = decrypt(key, iv, ciphertext)

    assert decrypted == plaintext


# =========================================================
# decrypt
# =========================================================


@pytest.mark.parametrize(
    "plaintext",
    [
        b"",
        b"binary payload",
        bytes(range(128)),
    ],
)
def test_decrypt_returns_original_bytes_plaintext(
    plaintext: bytes,
) -> None:
    key, iv, ciphertext = encrypt(plaintext)

    decrypted = decrypt(key, iv, ciphertext)

    assert isinstance(decrypted, bytes)

    assert decrypted == plaintext


@pytest.mark.parametrize(
    "plaintext",
    [
        "",
        "hello world",
        "秘密メッセージ",
        "🚀 secure payload",
    ],
)
def test_decrypt_returns_original_string_plaintext(
    plaintext: str,
) -> None:
    key, iv, ciphertext = encrypt(plaintext)

    decrypted = decrypt(key, iv, ciphertext)

    assert isinstance(decrypted, str)

    assert decrypted == plaintext


def test_decrypt_with_wrong_key_raises_unicode_decode_error() -> None:
    plaintext = "top secret"

    _, iv, ciphertext = encrypt(plaintext)

    wrong_key, _, _ = encrypt("other message")

    with pytest.raises(UnicodeDecodeError):
        decrypt(
            wrong_key,
            iv,
            ciphertext,
        )


def test_decrypt_with_wrong_iv_raises_unicode_decode_error() -> None:
    plaintext = "top secret"

    key, _, ciphertext = encrypt(plaintext)

    _, wrong_iv, _ = encrypt("other message")

    with pytest.raises(UnicodeDecodeError):
        decrypt(
            key,
            wrong_iv,
            ciphertext,
        )


@pytest.mark.parametrize(
    ("key", "iv", "ciphertext"),
    [
        ("invalid-base64", "aGVsbG8=", "aGVsbG8="),
        ("aGVsbG8=", "invalid-base64", "aGVsbG8="),
        ("aGVsbG8=", "aGVsbG8=", "invalid-base64"),
    ],
)
def test_decrypt_invalid_base64_raises_exception(
    key: str,
    iv: str,
    ciphertext: str,
) -> None:
    with pytest.raises(Exception):  # noqa: B017
        decrypt(key, iv, ciphertext)


def test_decrypt_invalid_key_size_raises_value_error() -> None:
    invalid_key = b"short-key"

    valid_iv = b64decode(b"AAAAAAAAAAAAAAAAAAAAAA==")

    valid_ciphertext = b"hello"

    with pytest.raises(ValueError):
        decrypt(
            invalid_key,
            valid_iv,
            valid_ciphertext,
        )


# =========================================================
# Roundtrip behavior
# =========================================================


@pytest.mark.parametrize(
    "plaintext",
    [
        "",
        "simple text",
        "multiline\ntext\npayload",
        "🔐 unicode payload",
    ],
)
def test_string_roundtrip_encryption_and_decryption(
    plaintext: str,
) -> None:
    key, iv, ciphertext = encrypt(plaintext)

    decrypted = decrypt(key, iv, ciphertext)

    assert decrypted == plaintext


@pytest.mark.parametrize(
    "plaintext",
    [
        b"",
        b"simple bytes",
        b"\x00\x01\x02",
        bytes(range(64)),
    ],
)
def test_bytes_roundtrip_encryption_and_decryption(
    plaintext: bytes,
) -> None:
    key, iv, ciphertext = encrypt(plaintext)

    decrypted = decrypt(key, iv, ciphertext)

    assert decrypted == plaintext


def test_encrypt_output_is_safe_for_base64_transport() -> None:
    key, iv, ciphertext = encrypt("transport-safe")

    # Should all be valid base64 decodable values
    assert b64decode(key.encode())
    assert b64decode(iv.encode())
    assert b64decode(ciphertext.encode())


def test_encrypt_and_decrypt_large_payload() -> None:
    plaintext = "A" * 100_000

    key, iv, ciphertext = encrypt(plaintext)

    decrypted = decrypt(key, iv, ciphertext)

    assert decrypted == plaintext
