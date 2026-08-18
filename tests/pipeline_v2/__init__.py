"""Tests for production-oriented pipeline_v2 integration.

``unittest discover -s tests`` places this package before the repository root.
Extend the package path explicitly so imports still resolve the production
``pipeline_v2`` modules rather than treating this test package as their owner.
"""

from pathlib import Path

__path__.append(str(Path(__file__).resolve().parents[2] / "pipeline_v2"))
