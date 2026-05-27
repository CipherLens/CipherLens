# Official API knowledge snippets: botan

Library: botan
Version: 3.10.0
Source file: /home/wen/work/clean_sources/botan-3.10.0/src/lib/math/bigint/big_io.cpp
Knowledge type: api_constraints

## Snippet 1

```c
*/
std::ostream& operator<<(std::ostream& stream, const BigInt& n) {
   const auto stream_flags = stream.flags();
   if((stream_flags & std::ios::oct) != 0) {
      throw Invalid_Argument("Octal output of BigInt not supported");
   }

   const size_t base = (stream_flags & std::ios::hex) != 0 ? 16 : 10;

   if(base == 10) {
      stream << n.to_dec_string();
   } else {
      stream << n.to_hex_string();
   }

   if(!stream.good()) {
      throw Stream_IO_Error("BigInt output operator has failed");
   }
   return stream;
}

/*
* Read the BigInt from a stream
*/
std::istream& operator>>(std::istream& stream, BigInt& n) {
   std::string str;
   std::getline(stream, str);
   if(stream.bad() || (stream.fail() && !stream.eof())) {
```

## Snippet 2

```c
const auto stream_flags = stream.flags();
   if((stream_flags & std::ios::oct) != 0) {
      throw Invalid_Argument("Octal output of BigInt not supported");
   }

   const size_t base = (stream_flags & std::ios::hex) != 0 ? 16 : 10;

   if(base == 10) {
      stream << n.to_dec_string();
   } else {
      stream << n.to_hex_string();
   }

   if(!stream.good()) {
      throw Stream_IO_Error("BigInt output operator has failed");
   }
   return stream;
}

/*
* Read the BigInt from a stream
*/
std::istream& operator>>(std::istream& stream, BigInt& n) {
   std::string str;
   std::getline(stream, str);
   if(stream.bad() || (stream.fail() && !stream.eof())) {
      throw Stream_IO_Error("BigInt input operator has failed");
   }
```

