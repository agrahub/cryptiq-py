import string

import pytest

from cryptiq.random import Format, random

# =========================================================
# Format
# =========================================================


def test_format_choices_returns_all_values() -> None:
    choices = Format.choices()

    assert choices == (
        "bytes",
        "hex",
        "string",
    )


def test_format_choices_returns_tuple_of_strings() -> None:
    choices = Format.choices()

    assert isinstance(choices, tuple)

    assert all(isinstance(choice, str) for choice in choices)


# =========================================================
# random - bytes
# =========================================================


def test_random_bytes_returns_bytes() -> None:
    token = random(Format.BYTES)

    assert isinstance(token, bytes)


@pytest.mark.parametrize(
    "nbytes",
    [1, 4, 16, 32],
)
def test_random_bytes_respects_nbytes(
    nbytes: int,
) -> None:
    token = random(
        Format.BYTES,
        nbytes,
    )

    assert isinstance(token, bytes)

    assert len(token) == nbytes


def test_random_bytes_generates_unique_values() -> None:
    first = random(Format.BYTES)
    second = random(Format.BYTES)

    assert first != second


def test_random_bytes_applies_prefix() -> None:
    token = random(
        Format.BYTES,
        prefix=b"pre_",
    )

    assert token.startswith(b"pre_")


def test_random_bytes_applies_suffix() -> None:
    token = random(
        Format.BYTES,
        suffix=b"_suf",
    )

    assert token.endswith(b"_suf")


def test_random_bytes_applies_prefix_and_suffix() -> None:
    token = random(
        Format.BYTES,
        prefix=b"pre_",
        suffix=b"_suf",
    )

    assert token.startswith(b"pre_")
    assert token.endswith(b"_suf")


def test_random_bytes_invalid_prefix_type_raises_type_error() -> None:
    with pytest.raises(TypeError):
        random(Format.BYTES, prefix="invalid")  # pyright: ignore[reportArgumentType, reportCallIssue]


def test_random_bytes_invalid_suffix_type_raises_type_error() -> None:
    with pytest.raises(TypeError):
        random(Format.BYTES, suffix="invalid")  # pyright: ignore[reportArgumentType, reportCallIssue]


# =========================================================
# random - hex
# =========================================================


def test_random_hex_returns_string() -> None:
    token = random(Format.HEX)

    assert isinstance(token, str)


@pytest.mark.parametrize(
    "nbytes",
    [1, 4, 16, 32],
)
def test_random_hex_respects_nbytes(
    nbytes: int,
) -> None:
    token = random(
        Format.HEX,
        nbytes,
    )

    assert isinstance(token, str)

    # Hex encoding doubles the size
    assert len(token) == nbytes * 2


def test_random_hex_generates_unique_values() -> None:
    first = random(Format.HEX)
    second = random(Format.HEX)

    assert first != second


def test_random_hex_contains_only_hex_characters() -> None:
    token = random(
        Format.HEX,
        32,
    )

    assert all(character in string.hexdigits for character in token)


def test_random_hex_applies_prefix() -> None:
    token = random(
        Format.HEX,
        prefix="pre_",
    )

    assert token.startswith("pre_")


def test_random_hex_applies_suffix() -> None:
    token = random(
        Format.HEX,
        suffix="_suf",
    )

    assert token.endswith("_suf")


def test_random_hex_applies_prefix_and_suffix() -> None:
    token = random(
        Format.HEX,
        prefix="pre_",
        suffix="_suf",
    )

    assert token.startswith("pre_")
    assert token.endswith("_suf")


def test_random_hex_invalid_prefix_type_raises_type_error() -> None:
    with pytest.raises(TypeError):
        random(Format.HEX, prefix=b"invalid")  # pyright: ignore[reportArgumentType, reportCallIssue]


def test_random_hex_invalid_suffix_type_raises_type_error() -> None:
    with pytest.raises(TypeError):
        random(Format.HEX, suffix=b"invalid")  # pyright: ignore[reportArgumentType, reportCallIssue]


# =========================================================
# random - string
# =========================================================


def test_random_string_returns_string() -> None:
    token = random(Format.STRING)

    assert isinstance(token, str)


@pytest.mark.parametrize(
    "nbytes",
    [1, 4, 16, 32],
)
def test_random_string_generates_non_empty_token(
    nbytes: int,
) -> None:
    token = random(
        Format.STRING,
        nbytes,
    )

    assert isinstance(token, str)

    assert len(token) > 0


def test_random_string_generates_unique_values() -> None:
    first = random(Format.STRING)
    second = random(Format.STRING)

    assert first != second


def test_random_string_applies_prefix() -> None:
    token = random(
        Format.STRING,
        prefix="pre_",
    )

    assert token.startswith("pre_")


def test_random_string_applies_suffix() -> None:
    token = random(
        Format.STRING,
        suffix="_suf",
    )

    assert token.endswith("_suf")


def test_random_string_applies_prefix_and_suffix() -> None:
    token = random(
        Format.STRING,
        prefix="pre_",
        suffix="_suf",
    )

    assert token.startswith("pre_")
    assert token.endswith("_suf")


def test_random_string_invalid_prefix_type_raises_type_error() -> None:
    with pytest.raises(TypeError):
        random(Format.STRING, prefix=b"invalid")  # pyright: ignore[reportArgumentType, reportCallIssue]


def test_random_string_invalid_suffix_type_raises_type_error() -> None:
    with pytest.raises(TypeError):
        random(Format.STRING, suffix=b"invalid")  # pyright: ignore[reportArgumentType, reportCallIssue]


def test_random_string_is_urlsafe() -> None:
    token = random(
        Format.STRING,
        32,
    )

    unsafe_characters = {
        "+",
        "/",
        "=",
        " ",
    }

    assert not any(character in unsafe_characters for character in token)


# =========================================================
# General behavior
# =========================================================


def test_random_default_format_returns_string() -> None:
    token = random()

    assert isinstance(token, str)


def test_random_default_format_matches_string_behavior() -> None:
    token = random()

    assert isinstance(token, str)

    assert len(token) > 0


@pytest.mark.parametrize(
    "format",
    [
        Format.BYTES,
        Format.HEX,
        Format.STRING,
    ],
)
def test_random_generates_non_empty_values(
    format: Format,
) -> None:
    token = random(format)

    assert len(token) > 0
