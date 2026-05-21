from enum import StrEnum

from typal.strings import ManyStrs


class Mode(StrEnum):
    DIGEST = "digest"
    OBJECT = "object"

    @classmethod
    def choices(cls) -> ManyStrs:
        return tuple(choice.value for choice in cls)
