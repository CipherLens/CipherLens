"""Types shared by the Trigger Template Interface foundation."""

from __future__ import annotations

from enum import Enum


SCHEMA_VERSION = "cipherlens.trigger_template_interface.v0.1"
INTERFACE_VERSION = "v0.1"


class SlotKind(str, Enum):
    INPUT = "INPUT"
    OBJECT = "OBJECT"
    OPERATION = "OPERATION"
    INTERVENTION = "INTERVENTION"
    OBSERVATION = "OBSERVATION"
    ORDER_ANCHOR = "ORDER_ANCHOR"
    STATE_ANCHOR = "STATE_ANCHOR"


class Multiplicity(str, Enum):
    ONE = "ONE"
    ZERO_OR_ONE = "ZERO_OR_ONE"
    ONE_OR_MORE = "ONE_OR_MORE"
    ZERO_OR_MORE = "ZERO_OR_MORE"


class ManifestError(ValueError):
    """Raised when a manifest cannot be deterministically built or validated."""

    def __init__(self, errors: list[str] | tuple[str, ...]) -> None:
        self.errors = tuple(sorted(dict.fromkeys(errors)))
        super().__init__("invalid Trigger Template Interface manifest:\n" + "\n".join(
            f"- {error}" for error in self.errors
        ))
