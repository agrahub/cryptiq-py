from typing import Annotated

from annotated_types import Ge, Le, MultipleOf
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa

type KeySize = Annotated[int, Ge(2048), Le(8192), MultipleOf(1024)]

type RSAPrivateKeyTypes = rsa.RSAPrivateKey | RSA.RsaKey
type RSAPublicKeyTypes = rsa.RSAPublicKey | RSA.RsaKey
type RSAKeyTypes = RSAPrivateKeyTypes | RSAPublicKeyTypes

type CryptographyRSAKeyPair = tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
type PycryptodomeRSAKeyPair = tuple[RSA.RsaKey, RSA.RsaKey]
type RSAKeyPairTypes = CryptographyRSAKeyPair | PycryptodomeRSAKeyPair
