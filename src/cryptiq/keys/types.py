from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)

type PrivateOrPublicKeyTypes = PrivateKeyTypes | PublicKeyTypes
type KeyPairTypes = tuple[PrivateKeyTypes, PublicKeyTypes]
