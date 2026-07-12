import unittest

from template_maker.cross_generator_from_adapters import (
    RSA_PUBLIC_SPKI_HEX,
    der_positive_control_block,
)
from template_maker.render_cases import is_valid_case


class DerSpkiPipelineTest(unittest.TestCase):
    def test_spki_fixture(self):
        spki = bytes.fromhex(RSA_PUBLIC_SPKI_HEX)

        self.assertEqual(len(spki), 162)
        self.assertEqual(
            spki[:22].hex(),
            "30819f300d06092a864886f70d010101050003818d00",
        )
        self.assertIn(
            bytes.fromhex("30818902818100"),
            spki,
        )

    def test_positive_control_generation(self):
        expected = {
            "d2i_PrivateKey": "d2i_PrivateKey(",
            "d2i_RSAPrivateKey": "d2i_RSAPrivateKey(",
            "d2i_RSA_PUBKEY": "d2i_RSA_PUBKEY(",
        }

        for api, token in expected.items():
            with self.subTest(api=api):
                block = der_positive_control_block(api, "der")
                self.assertIn(token, block)
                self.assertIn("positive_consumed_len", block)
                self.assertIn("return 2;", block)

    def test_parse_api_constraints(self):
        valid = {
            "RSA_DER_TOP_LEVEL_SEQUENCE_TRAILING_GARBAGE"
            "__OPENSSL_D2I_RSAPRIVATEKEY": (
                "private",
                "rsa_private",
            ),
            "RSA_DER_TOP_LEVEL_SEQUENCE_TRAILING_GARBAGE"
            "__OPENSSL_D2I_PRIVATEKEY": (
                "private",
                "pk_private",
            ),
            "RSA_DER_TOP_LEVEL_SEQUENCE_TRAILING_GARBAGE"
            "__OPENSSL_D2I_RSA_PUBKEY": (
                "public",
                "rsa_public",
            ),
        }

        for template_id, pair in valid.items():
            der_kind, parse_api_kind = pair

            values = {
                "DER_KIND": der_kind,
                "PARSE_API_KIND": parse_api_kind,
                "TRAILING_GARBAGE_BYTES": "020100",
                "TRAILING_GARBAGE_LEN": 3,
            }

            with self.subTest(template_id=template_id):
                self.assertTrue(
                    is_valid_case(template_id, values)
                )

        invalid_values = {
            "DER_KIND": "public",
            "PARSE_API_KIND": "rsa_private",
            "TRAILING_GARBAGE_BYTES": "020100",
            "TRAILING_GARBAGE_LEN": 3,
        }

        self.assertFalse(
            is_valid_case(
                "RSA_DER_TOP_LEVEL_SEQUENCE_TRAILING_GARBAGE"
                "__OPENSSL_D2I_RSA_PUBKEY",
                invalid_values,
            )
        )


if __name__ == "__main__":
    unittest.main()
