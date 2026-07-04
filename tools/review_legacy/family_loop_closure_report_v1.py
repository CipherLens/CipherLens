#!/usr/bin/env python3
"""Backward-compatible CLI wrapper for analysis.family_loop_closure."""

from __future__ import annotations

from analysis.family_loop_closure import main


if __name__ == "__main__":
    raise SystemExit(main())
