#include "Base64.hpp"
#include "PublicKey.hpp"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <exception>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

const char kCanonicalPublicKeyBase64[] =
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuwlKS6Lv26yM7IiRN6Ob3h/Af"
  "CcQtwcOZbyFz/kjCLgTR0c/Ry6iyZew2J8SY6MCdjUC7FaOaXaf0ajdKImwmdNW5"
  "IzS0ltOZxmD8YpCxyoDjjrmhiDEbwuXFcuCIoAEPpUppqC1GXkTl6lk8xmlx/Jyw"
  "nJqKSG6IawYJcGyf+wIDAQAB";

template<typename T, void (*FreeFunc)(T*)>
using openssl_ptr = std::unique_ptr<T, decltype(FreeFunc)>;

using EVPKeyPtr = openssl_ptr<EVP_PKEY, EVP_PKEY_free>;
using RSAPtr = openssl_ptr<RSA, RSA_free>;

struct CorpusCase
{
  std::string name;
  std::vector<unsigned char> der;
};

std::vector<unsigned char>
decode_canonical()
{
  const std::string decoded =
    DKIM::Conversion::Base64_Decode(kCanonicalPublicKeyBase64);
  return std::vector<unsigned char>(decoded.begin(), decoded.end());
}

std::string
base64_encode(const std::vector<unsigned char>& input)
{
  const std::size_t capacity = 4 * ((input.size() + 2) / 3);
  std::string output(capacity, '\0');
  const int written = EVP_EncodeBlock(
    reinterpret_cast<unsigned char*>(&output[0]),
    input.data(),
    static_cast<int>(input.size()));
  if (written < 0)
    throw std::runtime_error("EVP_EncodeBlock failed");
  output.resize(static_cast<std::size_t>(written));
  return output;
}

EVPKeyPtr
parse_spki(const std::vector<unsigned char>& der)
{
  const unsigned char* cursor = der.data();
  return EVPKeyPtr(
    d2i_PUBKEY(nullptr, &cursor, static_cast<long>(der.size())),
    EVP_PKEY_free);
}

std::vector<unsigned char>
serialize_spki(EVP_PKEY* key)
{
  const int size = i2d_PUBKEY(key, nullptr);
  if (size <= 0)
    throw std::runtime_error("i2d_PUBKEY size query failed");
  std::vector<unsigned char> der(static_cast<std::size_t>(size));
  unsigned char* cursor = der.data();
  if (i2d_PUBKEY(key, &cursor) != size)
    throw std::runtime_error("i2d_PUBKEY serialization failed");
  return der;
}

std::vector<unsigned char>
make_different_key_spki(const std::vector<unsigned char>& canonical)
{
  EVPKeyPtr reference = parse_spki(canonical);
  if (!reference)
    throw std::runtime_error("canonical fixture did not parse");

  RSAPtr rsa(EVP_PKEY_get1_RSA(reference.get()), RSA_free);
  if (!rsa)
    throw std::runtime_error("canonical fixture is not RSA");

  const BIGNUM* n = nullptr;
  const BIGNUM* e = nullptr;
  RSA_get0_key(rsa.get(), &n, &e, nullptr);
  BIGNUM* changed_n = BN_dup(n);
  BIGNUM* copied_e = BN_dup(e);
  if (!changed_n || !copied_e || BN_add_word(changed_n, 2) != 1) {
    BN_free(changed_n);
    BN_free(copied_e);
    throw std::runtime_error("failed to construct different RSA key");
  }

  RSAPtr changed_rsa(RSA_new(), RSA_free);
  if (!changed_rsa ||
      RSA_set0_key(changed_rsa.get(), changed_n, copied_e, nullptr) != 1) {
    BN_free(changed_n);
    BN_free(copied_e);
    throw std::runtime_error("RSA_set0_key failed");
  }

  EVPKeyPtr changed(EVP_PKEY_new(), EVP_PKEY_free);
  if (!changed || EVP_PKEY_set1_RSA(changed.get(), changed_rsa.get()) != 1)
    throw std::runtime_error("EVP_PKEY_set1_RSA failed");
  return serialize_spki(changed.get());
}

std::vector<CorpusCase>
make_corpus()
{
  const auto canonical = decode_canonical();
  std::vector<CorpusCase> cases;
  cases.push_back({ "canonical", canonical });

  auto tail_0500 = canonical;
  tail_0500.insert(tail_0500.end(), { 0x05, 0x00 });
  cases.push_back({ "tail_0500", tail_0500 });

  auto tail_3000 = canonical;
  tail_3000.insert(tail_3000.end(), { 0x30, 0x00 });
  cases.push_back({ "tail_3000", tail_3000 });

  auto tail_020100 = canonical;
  tail_020100.insert(tail_020100.end(), { 0x02, 0x01, 0x00 });
  cases.push_back({ "tail_020100", tail_020100 });

  cases.push_back({ "invalid_der", { 0x30, 0x00 } });
  cases.push_back({ "different_key", make_different_key_spki(canonical) });
  return cases;
}

std::string
sha256_hex(const std::vector<unsigned char>& input)
{
  unsigned char digest[SHA256_DIGEST_LENGTH];
  if (!SHA256(input.data(), input.size(), digest))
    throw std::runtime_error("SHA256 failed");

  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (unsigned char value : digest)
    output << std::setw(2) << static_cast<unsigned int>(value);
  return output.str();
}

std::string
json_escape(const std::string& input)
{
  std::ostringstream output;
  for (unsigned char value : input) {
    switch (value) {
      case '\\': output << "\\\\"; break;
      case '"': output << "\\\""; break;
      case '\n': output << "\\n"; break;
      case '\r': output << "\\r"; break;
      case '\t': output << "\\t"; break;
      default:
        if (value < 0x20) {
          output << "\\u" << std::hex << std::setw(4)
                 << std::setfill('0') << static_cast<unsigned int>(value)
                 << std::dec;
        } else {
          output << static_cast<char>(value);
        }
    }
  }
  return output.str();
}

} // namespace

int
main(int argc, char** argv)
{
  if (argc != 3) {
    std::cerr << "usage: parser_matrix_cpp IMPLEMENTATION REVISION\n";
    return 2;
  }

  const std::string implementation = argv[1];
  const std::string revision = argv[2];

  try {
    const auto canonical = decode_canonical();
    EVPKeyPtr reference = parse_spki(canonical);
    if (!reference)
      throw std::runtime_error("canonical reference key did not parse");

    for (const auto& test_case : make_corpus()) {
      bool accepted = false;
      bool key_equal = false;
      std::string canonical_hash;
      std::string error;

      try {
        const std::string record =
          "v=DKIM1; k=rsa; p=" + base64_encode(test_case.der) + ";";
        DKIM::PublicKey parsed;
        parsed.Parse(record);

        RSA* parsed_rsa = parsed.GetRSAPublicKey();
        if (!parsed_rsa)
          throw std::runtime_error("accepted record has no RSA key");

        EVPKeyPtr parsed_key(EVP_PKEY_new(), EVP_PKEY_free);
        if (!parsed_key ||
            EVP_PKEY_set1_RSA(parsed_key.get(), parsed_rsa) != 1)
          throw std::runtime_error("EVP_PKEY_set1_RSA failed");

        const auto normalized = serialize_spki(parsed_key.get());
        accepted = true;
        key_equal = EVP_PKEY_eq(reference.get(), parsed_key.get()) == 1;
        canonical_hash = sha256_hex(normalized);
      } catch (const std::exception& exception) {
        error = exception.what();
      }

      std::cout
        << "{\"implementation\":\"" << json_escape(implementation)
        << "\",\"revision\":\"" << json_escape(revision)
        << "\",\"case\":\"" << json_escape(test_case.name)
        << "\",\"accepted\":" << (accepted ? "true" : "false")
        << ",\"canonical_spki_sha256\":\"" << json_escape(canonical_hash)
        << "\",\"key_equal\":" << (key_equal ? "true" : "false")
        << ",\"error\":\"" << json_escape(error) << "\"}\n";
    }
  } catch (const std::exception& exception) {
    std::cerr << exception.what() << '\n';
    return 1;
  }

  return 0;
}
