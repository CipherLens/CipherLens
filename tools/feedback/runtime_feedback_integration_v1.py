#!/usr/bin/env python3
"""Backward-compatible CLI wrapper for analysis.runtime_feedback."""

from __future__ import annotations

from analysis.runtime_feedback import main


if __name__ == "__main__":
    raise SystemExit(main())
