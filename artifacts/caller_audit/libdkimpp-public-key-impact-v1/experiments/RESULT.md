# libdkim++ public-key parsing impact experiment

## Result

Final conclusion: `dkim_interoperability_difference`

The bounded local experiments confirm that the parser differential propagates through the libdkim++ `Validatory` chain. They do not establish a security vulnerability or an additional attacker security benefit.

## Scope and threat-model controls

Status: confirmed.

- The experiments used only deterministic local messages, an in-memory `CustomDNSResolver`, and public test key material.
- No real DNS lookup, mail server, domain, mailbox, DMARC evaluator, gateway, or filtering system was used.
- `attacker_controls_record_for_own_domain: true`
- `victim_domain_control: false`
- `victim_private_key_control: false`
- The external libdkim++ source worktree remained clean at `9defa162eebc644b006b7a51e92162640a810ee9`. Baseline and fix-control experiments used independent worktrees under `/tmp`.

## Environment

Status: confirmed.

- OpenSSL: 3.5.5, using headers and static libraries from `/home/yvxi/workplace/CryptoPoc/clean_sources/openssl-3.5.5`
- C++ compiler: Ubuntu Clang 18.1.3
- Instrumentation: ASan and UBSan; no runtime findings were reported
- Go: `go version go1.26.5 linux/amd64`
- Go archive SHA-256: `5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053`
- Go was executed only from `/tmp/cipherlens-go1.26.5/bin/go`, with local toolchain mode, module proxy disabled, and telemetry disabled

## Parser matrix

Status: confirmed. The complete matrix is in [parser_matrix.jsonl](parser_matrix.jsonl) and contains 18 rows.

| Case | libdkim++ baseline | libdkim++ fix-control | Go crypto/x509 |
| --- | --- | --- | --- |
| canonical | accept, equal | accept, equal | accept, equal |
| tail_0500 | accept, equal | reject | reject |
| tail_3000 | accept, equal | reject | reject |
| tail_020100 | accept, equal | reject | reject |
| invalid_der | reject | reject | reject |
| different_key | accept, not equal | accept, not equal | accept, not equal |

All accepted canonical and tailed inputs normalize to the same canonical SPKI SHA-256:

`7f23cb8c4f7c72fb3442c79f79b4c2f5c1d0bc1d366e0a9e8f1e76cf38d41253`

The different control key normalizes to:

`4ab731ac0530cf698d47b283d2f6f9bbcd39ff1914deeffa2b406e63f5af27d2`

The Go parser rejects each tailed case with `x509: trailing data after ASN.1 of public-key`.

## libdkim++ Validatory regression matrix

Status: confirmed. The complete matrix is in [dkim_regression_matrix.jsonl](dkim_regression_matrix.jsonl) and contains 16 rows.

The harness invokes `GetSignature`, `GetPublicKey`, and `CheckSignature` with a deterministic local `.eml` and an in-memory resolver.

| Case | Baseline | Fix-control |
| --- | --- | --- |
| canonical | pass | pass |
| tail_0500 | pass | permerror at key parsing |
| tail_3000 | pass | permerror at key parsing |
| tail_020100 | pass | permerror at key parsing |
| invalid_signature | fail: signature did not verify | fail: signature did not verify |
| different_key | fail: signature did not verify | fail: signature did not verify |
| revoked_empty_p | permerror: key revoked | permerror: key revoked |
| invalid_der | permerror: invalid DER | permerror: invalid DER |

The fix-control preserves the canonical success case and all negative controls. Its only observed behavior change is rejection of the three tailed SPKIs before signature verification.

## Interpretation

Confirmed:

- The baseline accepts three non-canonical SPKI byte strings that the fix-control and Go `crypto/x509.ParsePKIXPublicKey` reject.
- In the local baseline Validatory chain, those records retain the same RSA verification capability as the canonical record.
- Under the full-consumption fix-control, those records produce a permanent key-parsing error while the canonical record continues to pass.
- Invalid signatures, different keys, empty `p=`, and invalid DER do not pass.

Inferred:

- A caller comparing results from baseline libdkim++ and a strict parser could observe an interoperability difference for the three tailed records.
- Deploying the full-consumption check could turn previously accepted malformed records into DKIM permanent errors.

Unproven:

- Any additional authorization or security benefit unavailable through the canonical record.
- Any victim-domain impersonation, victim-key use, trust bypass, cache or revocation bypass, or policy bypass.
- Any effect on a real DMARC evaluator, mail gateway, filtering rule, or external service.
- A security vulnerability.

An own-domain signer who controls the tested DNS record and matching test key can already obtain the same DKIM pass with the canonical record. Therefore these experiments support an interoperability conclusion, not a security-impact conclusion.

## Test status

The existing test command reported:

```text
Ran 9 tests
OK (skipped=1)
```

No build directory, binary, private key, Go archive, Go toolchain, or large log is stored in the repository.
