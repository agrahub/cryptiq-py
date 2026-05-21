import pytest
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey

from cryptiq.encryptions.rsa import decrypt, encrypt

# =========================================================
# helpers
# =========================================================


def _generate_keys() -> tuple[RsaKey, RsaKey]:
    key = RSA.generate(2048)
    return key.publickey(), key


# =========================================================
# encrypt / decrypt roundtrip
# =========================================================


def test_rsa_encrypt_decrypt_roundtrip_bytes() -> None:
    public, private = _generate_keys()

    plaintext = b"hello secure world"

    ciphertext = encrypt(public, plaintext)
    decrypted = decrypt(ciphertext, private)

    assert isinstance(ciphertext, bytes)
    assert isinstance(decrypted, bytes)
    assert decrypted == plaintext


def test_rsa_encrypt_decrypt_roundtrip_str() -> None:
    public, private = _generate_keys()

    plaintext = "hello secure world"

    ciphertext = encrypt(public, plaintext)
    decrypted = decrypt(ciphertext, private)

    assert isinstance(ciphertext, str)
    assert isinstance(decrypted, str)
    assert decrypted == plaintext


# =========================================================
# type preservation
# =========================================================


def test_encrypt_output_matches_input_type() -> None:
    public, _ = _generate_keys()

    assert isinstance(encrypt(public, b"abc"), bytes)
    assert isinstance(encrypt(public, "abc"), str)


def test_decrypt_output_matches_ciphertext_type() -> None:
    public, private = _generate_keys()

    c1 = encrypt(public, b"abc")
    c2 = encrypt(public, "abc")

    assert isinstance(decrypt(c1, private), bytes)
    assert isinstance(decrypt(c2, private), str)


# =========================================================
# wrong key behavior
# =========================================================


def test_decrypt_with_wrong_key_fails() -> None:
    public1, _ = _generate_keys()
    _, private2 = _generate_keys()

    ciphertext = encrypt(public1, "top secret")

    # wrong private key should raise ValueError (OAEP failure)
    with pytest.raises(ValueError):
        decrypt(ciphertext, private2)


# =========================================================
# ciphertext format sanity (light check only)
# =========================================================


def test_ciphertext_is_base64_encoded() -> None:
    public, private = _generate_keys()

    ciphertext = encrypt(public, "hello")

    # base64 output should be ASCII-safe and decodable
    assert isinstance(ciphertext.encode(), bytes)

    # ensure decrypt still works (primary validation)
    assert decrypt(ciphertext, private) == "hello"
