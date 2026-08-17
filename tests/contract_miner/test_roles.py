import unittest

from contract_miner.roles import OBJECT_ROLES, OBSERVABLE_ROLES, OPERATION_ROLES


class RoleRegistryTests(unittest.TestCase):
    def test_role_kinds_have_independent_registries(self):
        self.assertIn("PARSE", OPERATION_ROLES)
        self.assertIn("encoded_input", OBJECT_ROLES)
        self.assertIn("consumed_length", OBSERVABLE_ROLES)
        self.assertFalse(OPERATION_ROLES & OBJECT_ROLES)
        self.assertFalse(OPERATION_ROLES & OBSERVABLE_ROLES)

    def test_operation_registry_preserves_v0x_roles(self):
        self.assertEqual(
            14,
            len(OPERATION_ROLES),
        )


if __name__ == "__main__":
    unittest.main()
