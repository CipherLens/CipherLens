# Official test/example call patterns: botan

Library: botan
Version: 3.10.0
Source file: /home/wen/work/clean_sources/botan-3.10.0/src/tests/test_bigint.cpp
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
}

      static Test::Result test_encode() {
         Test::Result result("BigInt encoding functions");

         const auto n1 = Botan::BigInt::from_u64(0xffff);
         const auto n2 = Botan::BigInt::from_u64(1023);

         const auto encoded_n1 = n1.serialize(256);
         const auto encoded_n2 = n2.serialize(256);
         const auto expected = Botan::concat(encoded_n1, encoded_n2);

         const auto encoded_n1_n2 = BigInt::encode_fixed_length_int_pair(n1, n2, 256);
         result.test_eq("encode_fixed_length_int_pair", encoded_n1_n2, expected);

         for(size_t i = 0; i < 256 - n1.bytes(); ++i) {
            if(encoded_n1[i] != 0) {
               result.test_failure("BigInt::serialize", "no zero byte");
            }
         }

         return result;
      }

      static Test::Result test_get_substring() {
         Test::Result result("BigInt get_substring");

         const size_t rbits = 1024;

         auto rng = Test::new_rng("get_substring");

         const Botan::BigInt r(*rng, rbits);

         for(size_t wlen = 1; wlen <= 32; ++wlen) {
            for(size_t offset = 0; offset != rbits + 64; ++offset) {
               const uint32_t val = r.get_substring(offset, wlen);

               Botan::BigInt t = r >> offset;
               t.mask_bits(wlen);
```

