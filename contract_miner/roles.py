"""Closed semantic-role registries for Vulnerability Contract v0.3."""

from __future__ import annotations

OPERATION_ROLES = frozenset({"INIT", "SETUP", "UPDATE", "FINAL", "PARSE", "VERIFY", "SIGN", "QUERY", "RESET", "REINIT", "DUP", "COPY", "FREE", "ABORT"})
OBJECT_ROLES = frozenset({"encoded_input", "stateful_context", "key_material", "output_buffer", "result_object", "parameter"})
OBSERVABLE_ROLES = frozenset({"return_value", "error_code", "operation_outcome", "output_bytes", "output_length", "consumed_length", "input_length", "object_state", "state_transition", "subsequent_behavior", "fatal_event", "timing"})
VALUE_TYPES = frozenset({"integer", "boolean", "bytes", "enum", "outcome", "state", "event", "duration"})
STATE_KINDS = frozenset({"initial", "intermediate", "terminal", "error", "invalid"})
INTERVENTION_KINDS = frozenset({"append_input_tail", "set_invalid_parameter", "state_reuse_sequence", "boundary_value", "value_substitution", "sequence_replay"})
PRECONDITION_PREDICATES = frozenset({"valid_object_plus_nonempty_external_tail", "invalid_pkcs7_padding", "same_identifier_equal_nonzero_reuse", "invalid_parameter", "state_matches"})

# Registries are deliberately separated by semantic role kind. Operation roles
# are not a global alias for object, mutation, state, or observation roles.

