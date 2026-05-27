# Official API knowledge snippets: botan

Library: botan
Version: 3.10.0
Source file: /home/wen/work/clean_sources/botan-3.10.0/src/lib/math/bigint/bigint.h
Knowledge type: api_constraints

## Snippet 1

```c
*/
      BOTAN_DEPRECATED("Deprecated no replacement") uint32_t to_u32bit() const;

      /**
       * Convert this value to a decimal string.
       * Warning: decimal conversions are relatively slow
       *
       * If the integer is zero then "0" is returned.
       * If the integer is negative then "-" is prefixed.
       */
      std::string to_dec_string() const;

      /**
       * Convert this value to a hexadecimal string.
       *
       * If the integer is negative then "-" is prefixed.
       * Then a prefix of "0x" is added.
       * Follows is a sequence of hexadecimal characters in uppercase.
       *
       * The number of hexadecimal characters is always an even number,
       * with a zero prefix being included if necessary.
       * For example encoding the integer "5" results in "0x05"
       */
      std::string to_hex_string() const;

      /**
       * @param n the offset to get a byte from
       * @result byte at offset n
```

## Snippet 2

```c
* Convert this value to a hexadecimal string.
       *
       * If the integer is negative then "-" is prefixed.
       * Then a prefix of "0x" is added.
       * Follows is a sequence of hexadecimal characters in uppercase.
       *
       * The number of hexadecimal characters is always an even number,
       * with a zero prefix being included if necessary.
       * For example encoding the integer "5" results in "0x05"
       */
      std::string to_hex_string() const;

      /**
       * @param n the offset to get a byte from
       * @result byte at offset n
       */
      uint8_t byte_at(size_t n) const;

      /**
       * Return the word at a specified position of the internal register
       * @param n position in the register
       * @return value at position n
       */
      word word_at(size_t n) const { return m_data.get_word_at(n); }

      BOTAN_DEPRECATED("Deprecated no replacement") void set_word_at(size_t i, word w) { m_data.set_word_at(i, w); }

      BOTAN_DEPRECATED("Deprecated no replacement") void set_words(const word w[], size_t len) {
```

## Snippet 3

```c
*/
      template <typename T = std::vector<uint8_t>>
      T serialize() const {
         return serialize<T>(this->bytes());
      }

      /**
       * Store BigInt-value in a given byte array
       * @param buf destination byte array for the integer value
       */
      BOTAN_DEPRECATED("Use BigInt::serialize_to") void binary_encode(uint8_t buf[]) const {
         this->serialize_to(std::span{buf, this->bytes()});
      }

      /**
       * Store BigInt-value in a given byte array. If len is less than
       * the size of the value, then it will be truncated. If len is
       * greater than the size of the value, it will be zero-padded.
       * If len exactly equals this->bytes(), this function behaves identically
       * to binary_encode.
       *
       * Zero-padding the binary encoding is useful to ensure that other
       * applications correctly parse the encoded value as "positive integer",
       * as a leading 1-bit may be interpreted as a sign bit.
       *
       * @param buf destination byte array for the integer value
       * @param len how many bytes to write
       */
```

## Snippet 4

```c
* If len exactly equals this->bytes(), this function behaves identically
       * to binary_encode.
       *
       * Zero-padding the binary encoding is useful to ensure that other
       * applications correctly parse the encoded value as "positive integer",
       * as a leading 1-bit may be interpreted as a sign bit.
       *
       * @param buf destination byte array for the integer value
       * @param len how many bytes to write
       */
      BOTAN_DEPRECATED("Use BigInt::serialize_to") void binary_encode(uint8_t buf[], size_t len) const;

      /**
       * Read integer value from a byte array with given size
       * @param buf byte array buffer containing the integer
       * @param length size of buf
       */
      BOTAN_DEPRECATED("Use BigInt::from_bytes") void binary_decode(const uint8_t buf[], size_t length) {
         this->assign_from_bytes(std::span{buf, length});
      }

      /**
       * Read integer value from a byte vector
       * @param buf the vector to load from
       */
      BOTAN_DEPRECATED("Use BigInt::from_bytes") void binary_decode(std::span<const uint8_t> buf) {
         this->assign_from_bytes(buf);
      }
```

## Snippet 5

```c
* Encode a BigInt to a byte array according to IEEE 1363
       * @param n the BigInt to encode
       * @param bytes the length of the resulting secure_vector<uint8_t>
       * @result a secure_vector<uint8_t> containing the encoded BigInt
       */
      BOTAN_DEPRECATED("Use BigInt::serialize")
      static secure_vector<uint8_t> encode_1363(const BigInt& n, size_t bytes) {
         return n.serialize<secure_vector<uint8_t>>(bytes);
      }

      BOTAN_DEPRECATED("Use BigInt::serialize_to") static void encode_1363(std::span<uint8_t> out, const BigInt& n) {
         n.serialize_to(out);
      }

      BOTAN_DEPRECATED("Use BigInt::serialize_to")
      static void encode_1363(uint8_t out[], size_t bytes, const BigInt& n) {
         n.serialize_to(std::span{out, bytes});
      }

      /**
       * Encode two BigInt to a byte array according to IEEE 1363
       * @param n1 the first BigInt to encode
       * @param n2 the second BigInt to encode
       * @param bytes the length of the encoding of each single BigInt
       * @result a secure_vector<uint8_t> containing the concatenation of the two encoded BigInt
       */
      BOTAN_DEPRECATED("Deprecated no replacement")
      static secure_vector<uint8_t> encode_fixed_length_int_pair(const BigInt& n1, const BigInt& n2, size_t bytes);
```

## Snippet 6

```c
*/
      BOTAN_DEPRECATED("Use BigInt::serialize")
      static secure_vector<uint8_t> encode_1363(const BigInt& n, size_t bytes) {
         return n.serialize<secure_vector<uint8_t>>(bytes);
      }

      BOTAN_DEPRECATED("Use BigInt::serialize_to") static void encode_1363(std::span<uint8_t> out, const BigInt& n) {
         n.serialize_to(out);
      }

      BOTAN_DEPRECATED("Use BigInt::serialize_to")
      static void encode_1363(uint8_t out[], size_t bytes, const BigInt& n) {
         n.serialize_to(std::span{out, bytes});
      }

      /**
       * Encode two BigInt to a byte array according to IEEE 1363
       * @param n1 the first BigInt to encode
       * @param n2 the second BigInt to encode
       * @param bytes the length of the encoding of each single BigInt
       * @result a secure_vector<uint8_t> containing the concatenation of the two encoded BigInt
       */
      BOTAN_DEPRECATED("Deprecated no replacement")
      static secure_vector<uint8_t> encode_fixed_length_int_pair(const BigInt& n1, const BigInt& n2, size_t bytes);

      /**
       * Return a span over the register
       *
```

