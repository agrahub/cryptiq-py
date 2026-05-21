from typing import overload

import bcrypt
from typal.unions import BytesOrStr


@overload
def hash(password: bytes) -> bytes: ...
@overload
def hash(password: str) -> str: ...
def hash(password: BytesOrStr) -> BytesOrStr:
    """
    Hash a password using bcrypt with a randomly generated salt.

    This function automatically handles string and bytes conversion
    while preserving the input type in the returned hash.

    The bcrypt algorithm is intentionally computationally expensive,
    making it suitable for secure password storage and resistant to
    brute-force attacks.

    Args:
        password:
            Plaintext password to hash.

    Returns:
        The bcrypt password hash.

        - `bytes` input returns `bytes`
        - `str` input returns `str`

    Raises:
        TypeError:
            If `password` is not a supported type.

    Notes:
        A new random salt is generated for every call, meaning identical
        passwords will produce different hashes.

    Example:
        >>> password_hash = hash("my-secure-password")
    """
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password

    hash = bcrypt.hashpw(password=password_bytes, salt=bcrypt.gensalt())

    if isinstance(password, str):
        return hash.decode()

    return hash


@overload
def verify(password: bytes, hash: bytes) -> bool: ...
@overload
def verify(password: str, hash: str) -> bool: ...
def verify(password: BytesOrStr, hash: BytesOrStr) -> bool:
    """
    Verify a plaintext password against a bcrypt hash.

    This function securely compares a plaintext password with a
    previously generated bcrypt hash using bcrypt's built-in
    verification mechanism.

    Args:
        password:
            Plaintext password to verify.

        hash:
            Existing bcrypt password hash.

    Returns:
        `True` if the password matches the hash, otherwise `False`.

    Raises:
        TypeError:
            If the provided arguments are not supported types.

        ValueError:
            If the provided hash is malformed or invalid.

    Notes:
        Password comparison is performed using bcrypt's secure
        verification routine, which is designed to resist timing attacks.

    Example:
        >>> verify("my-password", password_hash)
        True
    """
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password

    if isinstance(hash, str):
        hash_bytes = hash.encode()
    else:
        hash_bytes = hash

    return bcrypt.checkpw(password=password_bytes, hashed_password=hash_bytes)
