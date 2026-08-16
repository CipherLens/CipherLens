"""Provider-neutral interface for future agent-backed analysis.

No concrete SDK or model provider is implemented here.  Callers inject an
implementation, which keeps orchestration independent from provider details.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AgentProvider(ABC):
    """Minimal interface consumed by the ImpactLift runner."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return a stable provider identifier for artifact provenance."""

    @abstractmethod
    def analyze(self, context_pack: dict[str, Any]) -> dict[str, Any]:
        """Return one structured ImpactLift exploration payload."""
