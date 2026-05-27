# Official test/example call patterns: botan

Library: botan
Version: 3.10.0
Source file: /home/wen/work/clean_sources/botan-3.10.0/src/tests/test_ecdsa.cpp
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
const std::vector<uint8_t> msg = vars.get_req_bin("Msg");
         const auto expected_pubkey = vars.get_req_bin("Pubkey");

         try {
            Botan::ECDSA_PublicKey pubkey(group, msg, R, S, V);
            result.test_eq("Pubkey X coordinate", pubkey.public_key_bits(), expected_pubkey);

            const uint8_t computed_V = pubkey.recovery_param(msg, R, S);
            result.test_eq("Recovery param is correct", static_cast<size_t>(computed_V), static_cast<size_t>(V));

            Botan::PK_Verifier verifier(pubkey, "Raw");

            auto sig = Botan::BigInt::encode_fixed_length_int_pair(R, S, group.get_order_bytes());

            result.confirm("Signature verifies", verifier.verify_message(msg, sig));
         } catch(Botan::Exception& e) {
            result.test_failure("Failed to recover ECDSA public key", e.what());
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecdsa_key_recovery", ECDSA_Key_Recovery_Tests);

   #endif

class ECDSA_Invalid_Key_Tests final : public Text_Based_Test {
   public:
      ECDSA_Invalid_Key_Tests() : Text_Based_Test("pubkey/ecdsa_invalid.vec", "Group,InvalidKeyX,InvalidKeyY") {}

      bool clear_between_callbacks() const override { return false; }

      bool skip_this_test(const std::string& /*header*/, const VarMap& vars) override {
         return !Botan::EC_Group::supports_named_group(vars.get_req_str("Group"));
      }

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("ECDSA invalid keys");
```

