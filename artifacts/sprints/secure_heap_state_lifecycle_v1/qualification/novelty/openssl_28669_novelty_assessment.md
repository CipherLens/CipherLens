# OPENSSL-ISSUE-28669 Novelty Assessment

## Current Actual Version

The current sprint and minimal reproducers use local OpenSSL:

```text
OpenSSL 3.5.5 27 Jan 2026
```

The version is high-confidence because compile commands, static archive linkage,
and the version probe all point to `${CLEAN_SOURCES_ROOT}/openssl-3.5.5`.

## Historical Version Evidence

The local `OPENSSL-ISSUE-28669` artifact records local validation against:

```text
OpenSSL 3.0.13 / libcrypto.so.3
```

It does not identify original reported version, affected versions, fixed
version, or patch commit.

## Classification

```text
current_version_robustness_candidate_with_unknown_historical_overlap
```

This is not just a proven historical reproduction, because the current actual
version is OpenSSL 3.5.5 and the historical artifact only documents local
OpenSSL 3.0.13 validation. It is also not yet a proven regression candidate,
because no fixed version or patch commit is known locally.

## Claim Boundary

```yaml
can_claim_new_vulnerability: false
can_claim_new_candidate: true
```

The correct wording is: current-version robustness candidate with unknown
historical overlap, pending upstream/version confirmation.
