#!/usr/bin/env python3
"""Backward-compatible CLI wrapper for template_maker.family_case_renderer."""

from __future__ import annotations

from template_maker.family_case_renderer import main


if __name__ == "__main__":
    raise SystemExit(main())
