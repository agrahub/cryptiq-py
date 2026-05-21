from enum import StrEnum

from typal.strings import ManyStrs


class Format(StrEnum):
    BYTES = "bytes"
    STRING = "string"

    @classmethod
    def choices(cls) -> ManyStrs:
        return tuple(choice.value for choice in cls)


class KeyType(StrEnum):
    PRIVATE = "private"
    PUBLIC = "public"

    @classmethod
    def choices(cls) -> ManyStrs:
        return tuple(choice.value for choice in cls)
