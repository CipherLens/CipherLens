"""Canonical Template--CandidateBinding Merge v0.1 foundation."""

from template_binding_merge.canonical import *
from template_binding_merge.model import *
from template_binding_merge.adaptation import apply_adaptation, build_adaptation_proposal
from template_binding_merge.completion import programmatic_complete
from template_binding_merge.gate import validate_merge_gate
from template_binding_merge.merge import construct_merge
from template_binding_merge.registry import validate_merged_source
from template_binding_merge.render import render_base_source
from template_binding_merge.capture_region import (
    make_merge_capture_binding,
    make_source_map_capture_extension,
)

__all__ = [name for name in globals() if not name.startswith("_")]
