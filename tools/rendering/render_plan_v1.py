#!/usr/bin/env python3
"""Backward-compatible CLI wrapper for template_maker.family_render_plan."""

from __future__ import annotations

from template_maker.family_render_plan import main


if __name__ == "__main__":
    raise SystemExit(main())
