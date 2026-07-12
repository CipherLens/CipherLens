#include "PublicKey.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

template<typename T, void (*FreeFunc)(T*)>
using openssl_ptr = std::unique_ptr<T, decltype(FreeFunc)>;

using EVPKeyPtr = openssl_ptr<EVP_PKEY, EVP_PKEY_free>;
using EVPKeyCtxPtr = openssl_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using EVPMdCtxPtr = openssl_ptr<EVP_MD_CTX, EVP_MD_CTX_free>;

EVPKeyPtr
generate_rsa_key()
{
  EVPKeyCtxPtr ctx(
    EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr),
    EVP_PKEY_CTX_free);

  if (!ctx ||
      EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
      EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) <= 0) {
    throw std::runtime_error("RSA key generation initialization failed");
  }

  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0 || raw == nullptr) {
    throw std::runtime_error("RSA key generation failed");
  }

  return EVPKeyPtr(raw, EVP_PKEY_free);
}

std::vector<unsigned char>
serialize_spki(EVP_PKEY* key)
{
  const int size = i2d_PUBKEY(key, nullptr);
  if (size <= 0) {
    throw std::runtime_error("i2d_PUBKEY size query failed");
  }

  std::vector<unsigned char> der(static_cast<std::size_t>(size));
  unsigned char* cursor = der.data();

  if (i2d_PUBKEY(key, &cursor) != size) {
    throw std::runtime_error("i2d_PUBKEY serialization failed");
  }

  return der;
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

  if (written < 0) {
    throw std::runtime_error("EVP_EncodeBlock failed");
  }

  output.resize(static_cast<std::size_t>(written));
  return output;
}

std::vector<unsigned char>
sign_message(EVP_PKEY* private_key,
             const std::vector<unsigned char>& message)
{
  EVPMdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

  if (!ctx ||
      EVP_DigestSignInit(
        ctx.get(), nullptr, EVP_sha256(), nullptr, private_key) <= 0 ||
      EVP_DigestSignUpdate(
        ctx.get(), message.data(), message.size()) <= 0) {
    throw std::runtime_error("EVP_DigestSign initialization failed");
  }

  std::size_t signature_size = 0;
  if (EVP_DigestSignFinal(ctx.get(), nullptr, &signature_size) <= 0) {
    throw std::runtime_error("EVP_DigestSign size query failed");
  }

  std::vector<unsigned char> signature(signature_size);
  if (EVP_DigestSignFinal(
        ctx.get(), signature.data(), &signature_size) <= 0) {
    throw std::runtime_error("EVP_DigestSign failed");
  }

  signature.resize(signature_size);
  return signature;
}

bool
verify_signature(EVP_PKEY* public_key,
                 const std::vector<unsigned char>& message,
                 const std::vector<unsigned char>& signature)
{
  EVPMdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

  if (!ctx ||
      EVP_DigestVerifyInit(
        ctx.get(), nullptr, EVP_sha256(), nullptr, public_key) <= 0 ||
      EVP_DigestVerifyUpdate(
        ctx.get(), message.data(), message.size()) <= 0) {
    return false;
  }

  return EVP_DigestVerifyFinal(
           ctx.get(), signature.data(), signature.size()) == 1;
}

struct CaseResult
{
  bool accepted = false;
  bool input_differs = false;
  bool canonical_roundtrip = false;
  bool public_key_equal = false;
  bool signature_verifies = false;
};

CaseResult
run_case(const std::string& name,
         const std::vector<unsigned char>& input,
         const std::vector<unsigned char>& canonical,
         EVP_PKEY* original_key,
         const std::vector<unsigned char>& message,
         const std::vector<unsigned char>& signature)
{
  CaseResult result;
  result.input_differs = input != canonical;

  try {
    const std::string record =
      "v=DKIM1; k=rsa; p=" + base64_encode(input) + ";";

    DKIM::PublicKey parsed;
    parsed.Parse(record);

    RSA* parsed_rsa = parsed.GetRSAPublicKey();
    result.accepted = parsed_rsa != nullptr;

    if (parsed_rsa != nullptr) {
      EVPKeyPtr parsed_key(EVP_PKEY_new(), EVP_PKEY_free);

      if (!parsed_key ||
          EVP_PKEY_set1_RSA(parsed_key.get(), parsed_rsa) != 1) {
        throw std::runtime_error("EVP_PKEY_set1_RSA failed");
      }

      result.canonical_roundtrip =
        serialize_spki(parsed_key.get()) == canonical;

      result.public_key_equal =
        EVP_PKEY_eq(original_key, parsed_key.get()) == 1;

      result.signature_verifies =
        verify_signature(
          parsed_key.get(), message, signature);
    }
  } catch (const std::exception&) {
    result.accepted = false;
  }

  std::cout
    << "case=" << name
    << " input_len=" << input.size()
    << " accepted=" << (result.accepted ? 1 : 0)
    << " input_differs=" << (result.input_differs ? 1 : 0)
    << " canonical_roundtrip="
    << (result.canonical_roundtrip ? 1 : 0)
    << " public_key_equal="
    << (result.public_key_equal ? 1 : 0)
    << " signature_verifies="
    << (result.signature_verifies ? 1 : 0)
    << '\n';

  return result;
}

} // namespace

int
main()
{
  try {
    auto key = generate_rsa_key();
    const auto canonical = serialize_spki(key.get());

    const std::vector<unsigned char> message{
      0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x4c, 0x65, 0x6e, 0x73
    };

    const auto signature = sign_message(key.get(), message);

    const auto baseline = run_case(
      "canonical",
      canonical,
      canonical,
      key.get(),
      message,
      signature);

    struct TailCase
    {
      const char* name;
      std::vector<unsigned char> tail;
    };

    const std::vector<TailCase> tails{
      { "tail_0500", { 0x05, 0x00 } },
      { "tail_3000", { 0x30, 0x00 } },
      { "tail_020100", { 0x02, 0x01, 0x00 } },
    };

    std::size_t accepted = 0;
    std::size_t rejected = 0;

    for (const auto& tail_case : tails) {
      auto input = canonical;
      input.insert(
        input.end(),
        tail_case.tail.begin(),
        tail_case.tail.end());

      const auto result = run_case(
        tail_case.name,
        input,
        canonical,
        key.get(),
        message,
        signature);

      accepted += result.accepted ? 1 : 0;
      rejected += result.accepted ? 0 : 1;
    }

    const bool baseline_ok =
      baseline.accepted &&
      baseline.canonical_roundtrip &&
      baseline.public_key_equal &&
      baseline.signature_verifies;

    std::cout
      << "summary=libdkimpp_public_key"
      << " baseline_ok=" << (baseline_ok ? 1 : 0)
      << " mutations_accepted=" << accepted
      << " mutations_rejected=" << rejected
      << '\n';

    return baseline_ok ? 0 : 2;
  } catch (const std::exception& ex) {
    std::cerr << "fatal=" << ex.what() << '\n';
    return 2;
  }
}
