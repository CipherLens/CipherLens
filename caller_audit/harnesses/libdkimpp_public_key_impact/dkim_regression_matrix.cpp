#include "Base64.hpp"
#include "Exception.hpp"
#include "Keys.hpp"
#include "Signatory.hpp"
#include "SignatoryOptions.hpp"
#include "Validatory.hpp"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <exception>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

const char kDomain[] = "impact.example.test";
const char kSelector[] = "cipherlens";
const char kCanonicalPublicKeyBase64[] =
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuwlKS6Lv26yM7IiRN6Ob3h/Af"
  "CcQtwcOZbyFz/kjCLgTR0c/Ry6iyZew2J8SY6MCdjUC7FaOaXaf0ajdKImwmdNW5"
  "IzS0ltOZxmD8YpCxyoDjjrmhiDEbwuXFcuCIoAEPpUppqC1GXkTl6lk8xmlx/Jyw"
  "nJqKSG6IawYJcGyf+wIDAQAB";

template<typename T, void (*FreeFunc)(T*)>
using openssl_ptr = std::unique_ptr<T, decltype(FreeFunc)>;

using EVPKeyPtr = openssl_ptr<EVP_PKEY, EVP_PKEY_free>;
using RSAPtr = openssl_ptr<RSA, RSA_free>;

struct ResolverContext
{
  std::string expected_query;
  std::string record;
};

struct RegressionCase
{
  std::string name;
  std::string record;
  bool invalidate_signature;
};

bool
memory_resolver(const std::string& query, std::string& result, void* data)
{
  ResolverContext* context = static_cast<ResolverContext*>(data);
  if (!context || query != context->expected_query)
    return false;
  result = context->record;
  return true;
}

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

std::string
record_for_der(const std::vector<unsigned char>& der)
{
  return "v=DKIM1; k=rsa; p=" + base64_encode(der) + ";";
}

std::string
unsigned_mail()
{
  return
    "From: CipherLens Test <sender@impact.example.test>\r\n"
    "To: Receiver <receiver@example.invalid>\r\n"
    "Subject: deterministic libdkim++ regression\r\n"
    "Date: Tue, 01 Jan 2030 00:00:00 +0000\r\n"
    "Message-ID: <libdkimpp-impact-v1@impact.example.test>\r\n"
    "\r\n"
    "CipherLens deterministic local regression body.\r\n";
}

std::string
make_signed_mail(bool invalidate_signature)
{
  const std::string message = unsigned_mail();
  std::stringstream input(message);
  DKIM::SignatoryOptions options;
  options
    .SetPrivateKey(DKIM_PRIVATEKEY)
    .SetDomain(kDomain)
    .SetSelector(kSelector)
    .SetDigestAlgorithm(DKIM::DKIM_A_SHA256)
    .SetSignatureAlgorithm(DKIM::DKIM_SA_RSA)
    .SetCanonModeHeader(DKIM::DKIM_C_RELAXED)
    .SetCanonModeBody(DKIM::DKIM_C_RELAXED);

  std::string header = DKIM::Signatory(input).CreateSignature(options);
  if (invalidate_signature) {
    const std::string marker = "\tb=";
    std::size_t position = header.find(marker);
    if (position == std::string::npos)
      throw std::runtime_error("generated DKIM header has no b= tag");
    position += marker.size();
    while (position < header.size() &&
           (header[position] == ' ' || header[position] == '\t' ||
            header[position] == '\r' || header[position] == '\n'))
      ++position;
    if (position >= header.size())
      throw std::runtime_error("generated DKIM b= tag is empty");
    header[position] = header[position] == 'A' ? 'B' : 'A';
  }
  return header + "\r\n" + message;
}

std::vector<RegressionCase>
make_cases()
{
  const auto canonical = decode_canonical();
  std::vector<RegressionCase> cases{
    { "canonical", record_for_der(canonical), false }
  };

  auto tail_0500 = canonical;
  tail_0500.insert(tail_0500.end(), { 0x05, 0x00 });
  cases.push_back({ "tail_0500", record_for_der(tail_0500), false });

  auto tail_3000 = canonical;
  tail_3000.insert(tail_3000.end(), { 0x30, 0x00 });
  cases.push_back({ "tail_3000", record_for_der(tail_3000), false });

  auto tail_020100 = canonical;
  tail_020100.insert(tail_020100.end(), { 0x02, 0x01, 0x00 });
  cases.push_back({ "tail_020100", record_for_der(tail_020100), false });

  cases.push_back({ "invalid_signature", record_for_der(canonical), true });
  cases.push_back({
    "different_key",
    record_for_der(make_different_key_spki(canonical)),
    false
  });
  cases.push_back({ "revoked_empty_p", "v=DKIM1; k=rsa; p=;", false });
  cases.push_back({
    "invalid_der",
    record_for_der(std::vector<unsigned char>{ 0x30, 0x00 }),
    false
  });
  return cases;
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
          output << "\\u00";
          static const char hex[] = "0123456789abcdef";
          output << hex[(value >> 4) & 0xf] << hex[value & 0xf];
        } else {
          output << static_cast<char>(value);
        }
    }
  }
  return output.str();
}

void
emit_result(const std::string& implementation,
            const std::string& revision,
            const std::string& case_name,
            const std::string& dns_key_parse,
            const std::string& dkim_result,
            const std::string& exception_class,
            const std::string& reason)
{
  std::cout
    << "{\"implementation\":\"" << json_escape(implementation)
    << "\",\"revision\":\"" << json_escape(revision)
    << "\",\"case\":\"" << json_escape(case_name)
    << "\",\"dns_key_parse\":\"" << json_escape(dns_key_parse)
    << "\",\"dkim_result\":\"" << json_escape(dkim_result)
    << "\",\"exception_class\":\"" << json_escape(exception_class)
    << "\",\"reason\":\"" << json_escape(reason) << "\"}\n";
}

} // namespace

int
main(int argc, char** argv)
{
  if (argc != 3) {
    std::cerr
      << "usage: dkim_regression_matrix IMPLEMENTATION REVISION\n";
    return 2;
  }

  const std::string implementation = argv[1];
  const std::string revision = argv[2];

  try {
    for (const auto& test_case : make_cases()) {
      std::string dns_key_parse = "not_attempted";
      std::string dkim_result = "error";
      std::string exception_class = "none";
      std::string reason;

      try {
        std::stringstream mail_input(
          make_signed_mail(test_case.invalidate_signature));
        DKIM::Validatory validator(mail_input);
        if (validator.GetSignatures().size() != 1)
          throw std::runtime_error("expected exactly one DKIM signature");

        ResolverContext resolver{
          std::string(kSelector) + "._domainkey." + kDomain,
          test_case.record
        };
        validator.CustomDNSResolver = memory_resolver;
        validator.CustomDNSData = &resolver;

        DKIM::Signature signature;
        validator.GetSignature(validator.GetSignatures().begin(), signature);

        DKIM::PublicKey public_key;
        dns_key_parse = "reject";
        validator.GetPublicKey(signature, public_key);
        dns_key_parse = "accept";

        validator.CheckSignature(
          *validator.GetSignatures().begin(), signature, public_key);
        dkim_result = "pass";
      } catch (DKIM::TemporaryError& exception) {
        dkim_result = exception.getAuthenticationResult();
        exception_class = "TemporaryError";
        reason = exception.what();
      } catch (DKIM::PermanentError& exception) {
        dkim_result = exception.getAuthenticationResult();
        exception_class = "PermanentError";
        reason = exception.what();
      } catch (const std::exception& exception) {
        dkim_result = "error";
        exception_class = "std::exception";
        reason = exception.what();
      }

      emit_result(
        implementation,
        revision,
        test_case.name,
        dns_key_parse,
        dkim_result,
        exception_class,
        reason);
    }
  } catch (const std::exception& exception) {
    std::cerr << exception.what() << '\n';
    return 1;
  }

  return 0;
}
