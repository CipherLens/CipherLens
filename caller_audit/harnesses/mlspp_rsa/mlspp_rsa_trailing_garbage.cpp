#include <bytes/bytes.h>
#include <hpke/signature.h>

#include <exception>
#include <iostream>
#include <string>
#include <vector>

using namespace MLS_NAMESPACE::bytes_ns;
using namespace MLS_NAMESPACE::hpke;

struct Result
{
  bool accepted = false;
  bool input_differs = false;
  bool canonical_roundtrip = false;
  bool public_key_equal = false;
  bool signature_verifies = false;
};

static Result
run_case(const std::string& name,
         const Signature& sig,
         const bytes& input,
         const bytes& canonical_private,
         const bytes& canonical_public,
         const bytes& message,
         const Signature::PublicKey& original_public)
{
  Result result;
  result.input_differs = input != canonical_private;

  try {
    auto decoded = sig.deserialize_private(input);
    result.accepted = true;
    result.canonical_roundtrip =
      sig.serialize_private(*decoded) == canonical_private;
    auto decoded_public = decoded->public_key();
    result.public_key_equal =
      sig.serialize(*decoded_public) == canonical_public;
    const auto signature = sig.sign(message, *decoded);
    result.signature_verifies =
      sig.verify(message, signature, original_public);
  } catch (const std::exception&) {
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

int
main()
{
  const auto& sig =
    Signature::get<Signature::ID::RSA_SHA256>();
  auto generated = Signature::generate_rsa(2048);
  const bytes canonical_private =
    sig.serialize_private(*generated);
  auto original_public = generated->public_key();
  const bytes canonical_public =
    sig.serialize(*original_public);
  const bytes message{ 0x00, 0x01, 0x02, 0x03 };

  const auto baseline = run_case(
    "canonical",
    sig,
    canonical_private,
    canonical_private,
    canonical_public,
    message,
    *original_public);

  struct Tail
  {
    const char* name;
    bytes value;
  };

  const std::vector<Tail> tails{
    { "tail_0500", bytes{ 0x05, 0x00 } },
    { "tail_3000", bytes{ 0x30, 0x00 } },
    { "tail_020100", bytes{ 0x02, 0x01, 0x00 } },
  };

  size_t accepted = 0;
  size_t rejected = 0;
  for (const auto& tail : tails) {
    bytes input = canonical_private;
    input += tail.value;
    const auto result = run_case(
      tail.name,
      sig,
      input,
      canonical_private,
      canonical_public,
      message,
      *original_public);
    accepted += result.accepted ? 1 : 0;
    rejected += result.accepted ? 0 : 1;
  }

  const bool baseline_ok =
    baseline.accepted &&
    baseline.canonical_roundtrip &&
    baseline.public_key_equal &&
    baseline.signature_verifies;

  std::cout
    << "summary=mlspp_rsa_private"
    << " baseline_ok=" << (baseline_ok ? 1 : 0)
    << " mutations_accepted=" << accepted
    << " mutations_rejected=" << rejected
    << '\n';

  return baseline_ok ? 0 : 2;
}
