from __future__ import annotations

import unittest

from pathlib import Path
import yaml

from transfer_signature.evaluate import FACT_MATCHER_REGISTRY
from transfer_signature.model import ConstraintClass
from transfer_signature.registry import (
    CONSTRAINT_REGISTRY,
    FACT_PARAMETER_KEYS,
    validate_constraint_parameters,
    validate_fact_parameters,
)


class ConstraintRegistryTests(unittest.TestCase):
    def test_bundled_schema_registries_match_runtime_registries(self):
        package = Path(__file__).resolve().parents[2] / "transfer_signature"
        ts_schema = yaml.safe_load((package / "ts.schema.yaml").read_text())
        profile_schema = yaml.safe_load((package / "target_profile.schema.yaml").read_text())
        schema_constraint_types = {
            item
            for values in ts_schema["constraint_classes"].values()
            for item in values
        }
        self.assertEqual(set(CONSTRAINT_REGISTRY), schema_constraint_types)
        self.assertEqual(set(CONSTRAINT_REGISTRY), set(ts_schema["parameter_keys"]))
        self.assertEqual(set(FACT_PARAMETER_KEYS), set(profile_schema["fact_parameter_keys"]))

    def test_constraint_registry_is_exactly_frozen(self):
        self.assertEqual(
            {
                "supports_operation_role",
                "supports_object_role",
                "supports_precondition_shape",
                "permits_equivalent_intervention",
                "supports_execution_shape",
                "mandatory_complete_input_enforcement",
                "failure_output_transactionality",
                "atomic_clear_precludes_inconsistent_intermediate_state",
                "mandatory_terminalization_precludes_followup",
                "contract_observable_resolvable",
                "observable_set_correlatable",
            },
            set(CONSTRAINT_REGISTRY),
        )
        self.assertEqual(set(CONSTRAINT_REGISTRY), set(FACT_MATCHER_REGISTRY))

    def test_relation_and_family_names_are_not_constraint_types(self):
        forbidden = {
            "full_consumption_on_success",
            "input_consumption",
            "failure_output_integrity",
            "object_state_consistency",
        }
        self.assertFalse(forbidden.intersection(CONSTRAINT_REGISTRY))

    def test_classes_and_fact_types_are_closed(self):
        self.assertEqual(5, sum(spec.constraint_class is ConstraintClass.REQUIRED_CAPABILITY for spec in CONSTRAINT_REGISTRY.values()))
        self.assertEqual(4, sum(spec.constraint_class is ConstraintClass.EXCLUDED_SEMANTIC for spec in CONSTRAINT_REGISTRY.values()))
        self.assertEqual(2, sum(spec.constraint_class is ConstraintClass.REQUIRED_OBSERVABILITY for spec in CONSTRAINT_REGISTRY.values()))
        self.assertEqual(11, len(FACT_PARAMETER_KEYS))

    def test_incompatible_parameter_shapes_are_rejected(self):
        errors = validate_constraint_parameters(
            "supports_operation_role",
            {"role": "VERIFY", "subject_role": "stateful_context", "score": "1"},
            "constraint.parameters",
        )
        self.assertTrue(any("score: unknown field" in item for item in errors), errors)
        errors = validate_fact_parameters(
            "operation_role",
            {"role": "NOT_A_ROLE", "subject_role": "stateful_context"},
            "fact.parameters",
        )
        self.assertTrue(any("unknown value" in item for item in errors), errors)


if __name__ == "__main__":
    unittest.main()
