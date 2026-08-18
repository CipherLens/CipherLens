"""Batch 5B tests without shadowing the production namespace."""

from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)
