from collections.abc import Iterable, Sequence
from datetime import timedelta

import jwt
from Crypto.PublicKey.RSA import RsaKey
from typal.dicts import StrToAnyDict
from typal.strings import OptStr
from typal.unions import BytesOrStr


def encode(
    payload: StrToAnyDict,
    *,
    key: RsaKey | BytesOrStr,
    algorithm: OptStr = "RS256",
    headers: StrToAnyDict | None = None,
) -> str:
    """
    Encode a JSON Web Token (JWT).

    This function generates a signed JWT using the provided payload and
    signing key. RSA keys are automatically exported to PEM format when
    required by the underlying JWT implementation.

    Args:
        payload:
            JWT payload containing claims to encode.

        key:
            Signing key used to generate the JWT signature.

            RSA keys are automatically exported to PEM format.

        algorithm:
            JWT signing algorithm.

        headers:
            Optional custom JWT headers.

    Returns:
        Encoded JWT string.

    Raises:
        TypeError:
            If the provided key or payload types are invalid.

        jwt.PyJWTError:
            If JWT encoding or signing fails.

    Notes:
        The default signing algorithm is `RS256`.

    Example:
        >>> token = encode(payload={"sub": "123"}, key=private_key)
    """
    if isinstance(key, RsaKey):
        key = key.export_key()
    return jwt.encode(
        payload=payload,
        key=key,
        algorithm=algorithm,
        headers=headers,
    )


def decode(
    token: BytesOrStr,
    *,
    key: RsaKey | BytesOrStr = "",
    algorithms: Sequence[str] | None = ("RS256",),
    audience: str | Iterable[str] | None = None,
    subject: OptStr = None,
    issuer: str | Sequence[str] | None = None,
    leeway: float | timedelta = 0,
) -> StrToAnyDict:
    """
    Decode and verify a JSON Web Token (JWT).

    This function validates the JWT signature and optionally verifies
    registered claims such as audience, issuer, and subject.

    RSA keys are automatically exported to PEM format when required by
    the underlying JWT implementation.

    Args:
        token:
            JWT token to decode and verify.

        key:
            Verification key used to validate the JWT signature.

            RSA keys are automatically exported to PEM format.

        algorithms:
            Allowed JWT signing algorithms.

        audience:
            Expected JWT audience claim.

        subject:
            Expected JWT subject claim.

        issuer:
            Expected JWT issuer claim or claims.

        leeway:
            Allowed clock skew for validating time-based claims.

    Returns:
        Decoded JWT payload.

    Raises:
        jwt.PyJWTError:
            If token decoding, validation, or signature verification fails.

        TypeError:
            If provided argument types are invalid.

    Notes:
        Signature verification is enabled by default.

    Example:
        >>> payload = decode(token, key=public_key)
    """
    if isinstance(key, RsaKey):
        key = key.export_key()
    return jwt.decode(
        jwt=token,
        key=key,
        algorithms=algorithms,
        audience=audience,
        subject=subject,
        issuer=issuer,
        leeway=leeway,
    )
