# Official test/example call patterns: botan

Library: botan
Version: 3.10.0
Source file: /home/wen/work/clean_sources/botan-3.10.0/src/tests/test_dh.cpp
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
const BigInt g("2");
         const BigInt p("58458002095536094658683755258523362961421200751439456159756164191494576279467");
         const Botan::DL_Group group(p, g);

         const Botan::BigInt x("46205663093589612668746163860870963912226379131190812163519349848291472898748");
         auto privkey = std::make_unique<Botan::DH_PrivateKey>(group, x);

         auto kas = std::make_unique<Botan::PK_Key_Agreement>(*privkey, this->rng(), "Raw");

         result.test_throws("agreement input too big", "DH agreement - invalid key provided", [&kas]() {
            const BigInt too_big("584580020955360946586837552585233629614212007514394561597561641914945762794672");
            kas->derive_key(16, BigInt::encode(too_big));
         });

         result.test_throws("agreement input too small", "DH agreement - invalid key provided", [&kas]() {
            const BigInt too_small("1");
            kas->derive_key(16, BigInt::encode(too_small));
         });

         return {result};
      }
};

class DH_Invalid_Key_Tests final : public Text_Based_Test {
   public:
      DH_Invalid_Key_Tests() : Text_Based_Test("pubkey/dh_invalid.vec", "P,Q,G,InvalidKey") {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("DH invalid keys");

         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt q = vars.get_req_bn("Q");
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt pubkey = vars.get_req_bn("InvalidKey");

         Botan::DL_Group group(p, q, g);
```

## Call pattern 2

```c
const Botan::BigInt x("46205663093589612668746163860870963912226379131190812163519349848291472898748");
         auto privkey = std::make_unique<Botan::DH_PrivateKey>(group, x);

         auto kas = std::make_unique<Botan::PK_Key_Agreement>(*privkey, this->rng(), "Raw");

         result.test_throws("agreement input too big", "DH agreement - invalid key provided", [&kas]() {
            const BigInt too_big("584580020955360946586837552585233629614212007514394561597561641914945762794672");
            kas->derive_key(16, BigInt::encode(too_big));
         });

         result.test_throws("agreement input too small", "DH agreement - invalid key provided", [&kas]() {
            const BigInt too_small("1");
            kas->derive_key(16, BigInt::encode(too_small));
         });

         return {result};
      }
};

class DH_Invalid_Key_Tests final : public Text_Based_Test {
   public:
      DH_Invalid_Key_Tests() : Text_Based_Test("pubkey/dh_invalid.vec", "P,Q,G,InvalidKey") {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("DH invalid keys");

         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt q = vars.get_req_bn("Q");
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt pubkey = vars.get_req_bn("InvalidKey");

         Botan::DL_Group group(p, q, g);

         auto key = std::make_unique<Botan::DH_PublicKey>(group, pubkey);
         result.test_eq("public key fails check", key->check_key(this->rng(), false), false);
         return result;
      }
};
```

