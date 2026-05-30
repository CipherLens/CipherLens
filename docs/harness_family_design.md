# Harness Family Design

Harness families describe reusable oracle and harness-shape patterns. They are
not tied to a single PoC; each family should eventually map to shared candidate
scoring, adapter validation, cross-template generation, and result analysis
rules.

## buffer_canary_boundary

Use this family for caller-provided output buffers with explicit length
arguments and a canary placed after the buffer.

## der_pointer_consumption

Use this family for DER parsers where success/failure and pointer advancement
show whether the parser consumed the exact intended object or accepted trailing
bytes.

## x509_asn1_inner_boundary

Use this family for X.509 / ASN.1 parser paths where a nested substructure
boundary must be enforced and the observable result is a semantic parse
acceptance or rejection.

## return_code_outlen_semantic

适用场景：

API 返回错误时，caller-visible output length / output state 不应被污染。

典型漏洞：

invalid padding / invalid decode / finalization failure 返回错误码，但 output
length 被设置为非零、巨大值或不安全值。

required_observables:

- return_code
- output_length
- error_path_state

target_api_features:

- finalization_api
- invalid_padding_path
- caller_visible_output_length
- explicit output buffer or output length pointer

safe behavior:

error return + output length remains zero / safe

bug behavior:

error return + output length is nonzero / underflowed / unsafe

oracle_type:

`invalid_padding_output_length_oracle`

This family is not limited to `MBEDTLS-POC-0004`. It should be reused for
similar cryptographic-library interfaces where an error path must not pollute a
caller-visible output length or output-state value.

## bignum_arithmetic_semantic

适用场景：

大整数算术 API 的语义迁移，例如 subtraction / unsigned subtraction /
comparison。这个 family 关注 public API 层面能观察到的算术关系、返回码和
结果对象状态。

典型 source:

- `mbedtls_mpi_sub_abs`

典型 target:

- OpenSSL `BN_usub`
- OpenSSL `BN_sub`

required_observables:

- return_code
- result_bignum
- operand_relation
- arithmetic_result_state

target_api_features:

- bignum_arithmetic_api
- subtraction_operation
- caller-visible return code
- caller-visible result object

safe behavior:

target API fails or reports invalid relation when lhs < rhs for unsigned
subtraction, or target behavior is consistent with documented unsigned
subtraction constraints.

bug/semantic mismatch behavior:

target API unexpectedly succeeds, produces inconsistent result, or fails to
preserve the intended negative-result rejection semantics.

oracle_type:

`bignum_negative_result_rejection_oracle`

important limitation:

OpenSSL 3.x `BIGNUM` is opaque, so this family cannot directly model
source-level manual limb capacity or canary-after-limbs memory corruption.

`bignum_arithmetic_semantic` is not equivalent to `buffer_canary_boundary`. If
the original PoC's critical path is an internal limb out-of-bounds write, an
OpenSSL public API harness can only provide a semantic projection unless the
framework explicitly introduces a separate internal-instrumentation family.
