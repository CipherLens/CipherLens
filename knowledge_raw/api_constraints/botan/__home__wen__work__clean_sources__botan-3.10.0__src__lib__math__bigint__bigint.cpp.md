# Official API knowledge snippets: botan

Library: botan
Version: 3.10.0
Source file: /home/wen/work/clean_sources/botan-3.10.0/src/lib/math/bigint/bigint.cpp
Knowledge type: api_constraints

## Snippet 1

```c
return false;
   }

   if(other.is_negative() && this->is_negative()) {
      return bigint_ct_is_lt(other._data(), other.sig_words(), this->_data(), this->sig_words()).as_bool();
   }

   return bigint_ct_is_lt(this->_data(), this->sig_words(), other._data(), other.sig_words()).as_bool();
}

void BigInt::encode_words(word out[], size_t size) const {
   const size_t words = sig_words();

   if(words > size) {
      throw Encoding_Error("BigInt::encode_words value too large to encode");
   }

   clear_mem(out, size);
   copy_mem(out, _data(), words);
}

void BigInt::Data::set_to_zero() {
   m_reg.resize(m_reg.capacity());
   clear_mem(m_reg.data(), m_reg.size());
   m_sig_words = 0;
}

void BigInt::Data::mask_bits(size_t n) {
```

## Snippet 2

```c
return bigint_ct_is_lt(other._data(), other.sig_words(), this->_data(), this->sig_words()).as_bool();
   }

   return bigint_ct_is_lt(this->_data(), this->sig_words(), other._data(), other.sig_words()).as_bool();
}

void BigInt::encode_words(word out[], size_t size) const {
   const size_t words = sig_words();

   if(words > size) {
      throw Encoding_Error("BigInt::encode_words value too large to encode");
   }

   clear_mem(out, size);
   copy_mem(out, _data(), words);
}

void BigInt::Data::set_to_zero() {
   m_reg.resize(m_reg.capacity());
   clear_mem(m_reg.data(), m_reg.size());
   m_sig_words = 0;
}

void BigInt::Data::mask_bits(size_t n) {
   if(n == 0) {
      return set_to_zero();
   }
```

## Snippet 3

```c
*/
BigInt BigInt::abs() const {
   BigInt x = (*this);
   x.set_sign(Positive);
   return x;
}

/*
* Encode this number into bytes
*/
void BigInt::serialize_to(std::span<uint8_t> output) const {
   BOTAN_ARG_CHECK(this->bytes() <= output.size(), "Insufficient output space");

   this->binary_encode(output.data(), output.size());
}

/*
* Encode this number into bytes
*/
void BigInt::binary_encode(uint8_t output[], size_t len) const {
   const size_t full_words = len / sizeof(word);
   const size_t extra_bytes = len % sizeof(word);

   for(size_t i = 0; i != full_words; ++i) {
      const word w = word_at(i);
      store_be(w, output + (len - (i + 1) * sizeof(word)));
   }
```

