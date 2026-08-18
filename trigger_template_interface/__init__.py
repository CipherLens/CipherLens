"""Stable slot interface over current and legacy Trigger Templates."""

from trigger_template_interface.canonical import canonical_manifest_bytes, manifest_digest, normalize_manifest
from trigger_template_interface.manifest import adapt_normalized_template, build_manifest
from trigger_template_interface.model import INTERFACE_VERSION, SCHEMA_VERSION, ManifestError, Multiplicity, SlotKind
from trigger_template_interface.validate import validate_manifest, validate_manifest_or_raise

__all__ = [name for name in globals() if not name.startswith("_")]
