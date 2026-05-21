from enum import StrEnum

from typal.strings import ManyStrs


class Backend(StrEnum):
    CRYPTOGRAPHY = "cryptography"
    PYCRYPTODOME = "pycryptodome"

    @classmethod
    def choices(cls) -> ManyStrs:
        return tuple(choice.value for choice in cls)
