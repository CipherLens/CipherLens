# Official API knowledge snippets: botan

Library: botan
Version: 3.10.0
Source file: /home/wen/work/clean_sources/botan-3.10.0/src/lib/math/bigint/big_code.cpp
Knowledge type: api_constraints

## Snippet 1

```c
consteval size_t decimal_conversion_radix_digits() {
   if constexpr(sizeof(word) == 8) {
      return 19;
   } else {
      return 9;
   }
}

}  // namespace

std::string BigInt::to_dec_string() const {
   // Use the largest power of 10 that fits in a word
   constexpr word conversion_radix = decimal_conversion_radix();
   constexpr size_t radix_digits = decimal_conversion_radix_digits();

   // (over-)estimate of the number of digits needed; log2(10) ~ 3.3219
   const size_t digit_estimate = static_cast<size_t>(1 + (static_cast<double>(this->bits()) / 3.32));

   // (over-)estimate of db such that conversion_radix^db > *this
   const size_t digit_blocks = (digit_estimate + radix_digits - 1) / radix_digits;

   BigInt value = *this;
   value.set_sign(Positive);

   // Extract groups of digits into words
   std::vector<word> digit_groups(digit_blocks);

   for(size_t i = 0; i != digit_blocks; ++i) {
```

## Snippet 2

```c
s.push_back(*i + '0');  // assumes ASCII
   }

   if(s.empty()) {
      s += "0";
   }

   return s;
}

std::string BigInt::to_hex_string() const {
   const size_t this_bytes = this->bytes();
   std::vector<uint8_t> bits(std::max<size_t>(1, this_bytes));

   if(this_bytes > 0) {
      this->serialize_to(bits);
   }

   std::string hrep;
   if(is_negative()) {
      hrep += "-";
   }
   hrep += "0x";
   hrep += hex_encode(bits);
   return hrep;
}

/*
```

## Snippet 3

```c
hrep += "-";
   }
   hrep += "0x";
   hrep += hex_encode(bits);
   return hrep;
}

/*
* Encode two BigInt, with leading 0s if needed, and concatenate
*/
secure_vector<uint8_t> BigInt::encode_fixed_length_int_pair(const BigInt& n1, const BigInt& n2, size_t bytes) {
   if(n1.is_negative() || n2.is_negative()) {
      throw Encoding_Error("encode_fixed_length_int_pair: values must be positive");
   }
   if(n1.bytes() > bytes || n2.bytes() > bytes) {
      throw Encoding_Error("encode_fixed_length_int_pair: values too large to encode properly");
   }
   secure_vector<uint8_t> output(2 * bytes);
   BufferStuffer stuffer(output);
   n1.serialize_to(stuffer.next(bytes));
   n2.serialize_to(stuffer.next(bytes));
   return output;
}

BigInt BigInt::decode(std::span<const uint8_t> buf, Base base) {
   if(base == Binary) {
      return BigInt::from_bytes(buf);
   }
```

## Snippet 4

```c
if(n1.bytes() > bytes || n2.bytes() > bytes) {
      throw Encoding_Error("encode_fixed_length_int_pair: values too large to encode properly");
   }
   secure_vector<uint8_t> output(2 * bytes);
   BufferStuffer stuffer(output);
   n1.serialize_to(stuffer.next(bytes));
   n2.serialize_to(stuffer.next(bytes));
   return output;
}

BigInt BigInt::decode(std::span<const uint8_t> buf, Base base) {
   if(base == Binary) {
      return BigInt::from_bytes(buf);
   }
   return BigInt::decode(buf.data(), buf.size(), base);
}

/*
* Decode a BigInt
*/
BigInt BigInt::decode(const uint8_t buf[], size_t length, Base base) {
   if(base == Binary) {
      return BigInt::from_bytes(std::span{buf, length});
   } else if(base == Hexadecimal) {
      BigInt r;
      secure_vector<uint8_t> binary;

      if(length % 2 == 1) {
```

## Snippet 5

```c
BufferStuffer stuffer(output);
   n1.serialize_to(stuffer.next(bytes));
   n2.serialize_to(stuffer.next(bytes));
   return output;
}

BigInt BigInt::decode(std::span<const uint8_t> buf, Base base) {
   if(base == Binary) {
      return BigInt::from_bytes(buf);
   }
   return BigInt::decode(buf.data(), buf.size(), base);
}

/*
* Decode a BigInt
*/
BigInt BigInt::decode(const uint8_t buf[], size_t length, Base base) {
   if(base == Binary) {
      return BigInt::from_bytes(std::span{buf, length});
   } else if(base == Hexadecimal) {
      BigInt r;
      secure_vector<uint8_t> binary;

      if(length % 2 == 1) {
         // Handle lack of leading 0
         const char buf0_with_leading_0[2] = {'0', static_cast<char>(buf[0])};

         binary = hex_decode_locked(buf0_with_leading_0, 2);
```

## Snippet 6

```c
BigInt BigInt::decode(std::span<const uint8_t> buf, Base base) {
   if(base == Binary) {
      return BigInt::from_bytes(buf);
   }
   return BigInt::decode(buf.data(), buf.size(), base);
}

/*
* Decode a BigInt
*/
BigInt BigInt::decode(const uint8_t buf[], size_t length, Base base) {
   if(base == Binary) {
      return BigInt::from_bytes(std::span{buf, length});
   } else if(base == Hexadecimal) {
      BigInt r;
      secure_vector<uint8_t> binary;

      if(length % 2 == 1) {
         // Handle lack of leading 0
         const char buf0_with_leading_0[2] = {'0', static_cast<char>(buf[0])};

         binary = hex_decode_locked(buf0_with_leading_0, 2);

         if(length > 1) {
            binary += hex_decode_locked(cast_uint8_ptr_to_char(&buf[1]), length - 1, false);
         }
      } else {
         binary = hex_decode_locked(cast_uint8_ptr_to_char(buf), length, false);
```

## Snippet 7

```c
binary += hex_decode_locked(cast_uint8_ptr_to_char(&buf[1]), length - 1, false);
         }
      } else {
         binary = hex_decode_locked(cast_uint8_ptr_to_char(buf), length, false);
      }

      r.assign_from_bytes(binary);
      return r;
   } else if(base == Decimal) {
      BigInt r;
      // This could be made faster using the same trick as to_dec_string
      for(size_t i = 0; i != length; ++i) {
         const char c = buf[i];

         if(c < '0' || c > '9') {
            throw Invalid_Argument("BigInt::decode: invalid decimal char");
         }

         const uint8_t x = c - '0';
         BOTAN_ASSERT_NOMSG(x < 10);

         r *= 10;
         r += x;
      }
      return r;
   } else {
      throw Invalid_Argument("Unknown BigInt decoding method");
   }
```

## Snippet 8

```c
r.assign_from_bytes(binary);
      return r;
   } else if(base == Decimal) {
      BigInt r;
      // This could be made faster using the same trick as to_dec_string
      for(size_t i = 0; i != length; ++i) {
         const char c = buf[i];

         if(c < '0' || c > '9') {
            throw Invalid_Argument("BigInt::decode: invalid decimal char");
         }

         const uint8_t x = c - '0';
         BOTAN_ASSERT_NOMSG(x < 10);

         r *= 10;
         r += x;
      }
      return r;
   } else {
      throw Invalid_Argument("Unknown BigInt decoding method");
   }
}

}  // namespace Botan
```

