# Trace Format Spec (trace.jsonl) — v0.2

> Status: DRAFT v0.2 — incorporates the evidence-backed review of v0.1
> (all P0/P1/P2 items accepted). Codex must implement exactly what this file
> says. Target location: `docs/contract_miner/trace_format_spec.md`

## Changelog v0.1 → v0.2

- Header: added `pair_kind` (`same_library_fix` / `cross_library_reference`)
  so cross-library semantic-divergence material can be kept WITHOUT being
  mislabeled as a same-library vulnerability pair.
- `consumed_len`: strict direct-observation rule; reconstruction from
  generator/mutation metadata forbidden (anti-circularity).
- `sanitizer_event`: normalized values only (`asan_*`, `signal_*`); no raw
  stderr, addresses, or paths. `error_state`: stable codes/names only.
- §4: value types declared for all `out_state` keys.
- §5: MAC fixture ground truth rewritten (event alignment + ret
  conventions + pair binding); DER fixture bound to the real
  MBEDTLS-POC-0020 reproduction; stale-state fixture aligned to the real
  SIGSEGV evidence.
- §6: added M6 instrumentation notes (pre-call marker for crash
  attribution).
- §5.3 RESOLVED (human decision Q3, option a, 2026-08): lifecycle fixture
  bound to the real same-library pair OPENSSL-ISSUE-22842 (OpenSSL 3.1.1
  buggy vs repo-validated safe build), replacing the synthetic MAC pair.
  The OpenSSL-CMAC vs mbedTLS-PSA material remains available only as
  `pair_kind: cross_library_reference`.

## Changelog v0.2 → v0.2.1 (M1 prompt review backport)

- §3 T6 strengthened: a valid trace is now **semantically valid AND
  canonically encoded**; `load_trace` MUST reject non-canonical files with
  a T6 error instead of silently normalizing them. New §3.1 defines the
  Canonical Trace Encoding (field order, out_state key order, JSON
  separators, line endings). Rationale: plain "round-trip byte-identical"
  only holds for files the writer happened to produce; canonical encoding
  makes T6 a real, testable property of any input.
- §5 clarified: for the DER and stale-state fixtures, `role`,
  `state_before`, `state_after` stay `null` in M1 (M3 role/state
  abstraction fills them later). Only the lifecycle fixture (§5.3) carries
  spec-defined roles/states as ground truth. The word "PARSE event" in
  §5.1 describes the API kind, not a required `role` value.
- §3 T4 clarified: nullability is symmetric — `consumed_len == null`
  requires `input_len == null` and vice versa.
- §3 typing note: JSON integers MUST be strict (`true`/`false` are not
  valid integers; Python `bool` is an `int` subclass — validators must use
  exact type checks, no coercion).

## 1. Purpose

A `trace.jsonl` file records the observable behavior of ONE harness execution
on ONE library build (buggy or fixed). Differential mining (M2) consumes
aligned buggy/fixed trace pairs. The format extends the record philosophy of
`runner/compile_run.py` (one JSON object per line, self-contained records)
but models API-call-level events rather than case-level results.

Produced by: instrumented harness runs (M6, `contract_miner/exec/`) or
synthetic fixtures (M1, `tests/contract_miner/fixtures/traces/`).
Consumed by: `contract_miner.trace`, `contract_miner.divergence`,
`contract_miner.roles`, `contract_miner.minimize`.

## 2. File Structure

- UTF-8 JSON Lines, one record per line, no trailing blank lines.
- Line 1 MUST be a header record; all following lines MUST be event records.
- `seq` starts at 0 and increases by exactly 1 per event record.
- Deterministic: same execution ⇒ byte-identical file. No timestamps,
  no absolute paths, no environment-dependent fields.

### 2.1 Header record

```json
{"record_type": "header", "format": "cipherlens.trace.v2", "library": "mbedtls", "build": "buggy", "library_version": "3.6.0", "pattern_id": "MBEDTLS-POC-0020", "pair_kind": "same_library_fix", "source": "fixture"}
```

| field | type | required | notes |
|---|---|---|---|
| `record_type` | string | yes | literal `header` |
| `format` | string | yes | literal `cipherlens.trace.v2` |
| `library` | string | yes | lowercase |
| `build` | enum | yes | `buggy` or `fixed` (within the declared pair) |
| `library_version` | string | yes | must name a REAL version with repo evidence |
| `pattern_id` | string | yes | must reference a real pattern/issue in the repo |
| `pair_kind` | enum | yes | `same_library_fix`: same library, pre/post-patch builds — eligible to support vulnerability claims. `cross_library_reference`: strict-vs-permissive behavior across DIFFERENT libraries — yields **semantic divergence candidates only**, never a bug claim |
| `source` | enum | yes | `fixture` or `instrumented_run` |

### 2.2 Event record

```json
{"record_type": "event", "seq": 3, "api": "mbedtls_md_finish", "role": "FINAL", "state_before": "UPDATED", "state_after": "FINALIZED", "ret": 0, "consumed_len": null, "input_len": null, "out_state": {"tag_written": true}, "sanitizer_event": null, "error_state": null}
```

| field | type | required | notes |
|---|---|---|---|
| `record_type` | string | yes | literal `event` |
| `seq` | int | yes | 0-based, strictly +1 |
| `api` | string | yes | concrete API name, e.g. `mbedtls_md_finish` |
| `role` | string/null | yes | member of the role vocabulary (vc_schema_spec §2.2), or `null` before annotation (M3 fills it) |
| `state_before` | string/null | yes | UPPER_SNAKE or null if unknown |
| `state_after` | string/null | yes | same |
| `ret` | int/null | yes | RAW API return code, following the selected API's own convention (e.g. OpenSSL success = 1, PSA success = 0). Never normalized |
| `consumed_len` | int/null | yes | set ONLY when the API or immediate harness instrumentation **directly observes** the consumed position (e.g. OpenSSL `d2i_*` pointer advancement). MUST be null when the API exposes no such observation, and MUST NOT be reconstructed from mutation metadata, generator-known object boundaries, fixture labels, or expected behavior |
| `input_len` | int/null | yes | total input length when `consumed_len` is set; else null |
| `out_state` | object | yes | may be empty; only keys declared in §4, with their declared types |
| `sanitizer_event` | string/null | yes | a NORMALIZED sanitizer or fatal-signal finding attributable to this API event, e.g. `asan_null_deref` or `signal_sigsegv`. Raw stderr, addresses, paths, and source locations are forbidden; null if none. Use `asan_*` only when an actual ASan trace exists |
| `error_state` | string/null | yes | stable library error code/name only (no variable text); null if none |

## 3. Validation Rules (M1 acceptance scope)

- **T1** line 1 is a valid header; no second header; at least one event.
- **T2** `seq` is 0-based and increases by exactly 1.
- **T3** `role` is null or in the closed vocabulary; unknown non-null roles rejected.
- **T4** `consumed_len` set ⇒ `input_len` set, and `0 <= consumed_len <= input_len`.
- **T5** unknown fields rejected at every depth; missing required fields
  rejected; all violations reported in one pass, human-readable.
- **T6** a valid trace is semantically valid AND canonically encoded per
  §3.1. `load_trace` MUST reject a semantically valid but non-canonical
  file with a `T6 non-canonical trace encoding` error (no silent rewrite,
  no normalization). Consequently `dump_trace(load_trace(p))` is
  byte-identical to `p` for every valid `p`.
- **T7** `out_state` keys are restricted to §4 and values match declared
  types; `sanitizer_event` matches `^(asan|signal)_[a-z0-9_]+$` when set.

### 3.1 Canonical Trace Encoding

All valid trace files use exactly this encoding. Writers (`dump_trace`,
fixtures, M6 collectors) MUST produce it; loaders MUST reject deviations.

- **Header field order**: `record_type, format, library, build,
  library_version, pattern_id, pair_kind, source`.
- **Event field order**: `record_type, seq, api, role, state_before,
  state_after, ret, consumed_len, input_len, out_state, sanitizer_event,
  error_state`.
- **`out_state` key order**: registry order of §4 (`tag_written,
  tag_value, parse_result, len_cleared, reused_ptr_valid`); only present
  keys are emitted.
- **JSON encoding**: stdlib `json` with `ensure_ascii=False`,
  `sort_keys=False`, `separators=(",", ":")`. Never rely on dict
  insertion order.
- **Lines**: one record per line, `\n` line endings, no trailing spaces,
  no blank lines (internal or trailing), file ends with exactly one `\n`.
- **Strict JSON types**: integers via exact type check (`type(v) is int`);
  booleans via `type(v) is bool`; no coercion (`"1"→1`, `1→true`).

## 4. `out_state` Key Declaration

`out_state` may only carry safety-relevant observations that the oracle will
later compare. Keys and their exact value types (extend only by editing this
spec):

| key | type | meaning | family |
|---|---|---|---|
| `tag_written` | boolean | a MAC/tag output was produced by THIS event | mac_lifecycle |
| `tag_value` | string | emitted tag, lowercase even-length hex | mac_lifecycle |
| `parse_result` | enum | `success` / `reject` | parser families |
| `len_cleared` | boolean | internal length field cleared after zero-length update | stale-state |
| `reused_ptr_valid` | boolean | reused pointer readable after reuse step | stale-state |

Rationale: uncontrolled `out_state` keys would make divergence detection
(M2) noisy and non-reproducible.

## 5. Fixture Requirements (M1 deliverable)

Aligned pairs under `tests/contract_miner/fixtures/traces/`, each with a
one-paragraph `README.md` stating the expected divergence (ground truth for
M2). Fixture files are hand-written, short (< 25 events each), and MUST be
reviewed line-by-line by a human before M2 starts.

**Role/state annotation rule for fixtures:** only §5.3 (lifecycle) carries
spec-defined `role` / `state_after` values as ground truth. For §5.1 (DER)
and §5.2 (stale-state), `role`, `state_before`, `state_after` are `null` —
M1 MUST NOT perform role/state inference; M3 fills them later. (In §5.1,
"PARSE event" describes the API kind, not a required `role` value.)

### 5.1 DER pair — bound to the real MBEDTLS-POC-0020 reproduction

`der_buggy.jsonl` / `der_fixed.jsonl`, `pair_kind: same_library_fix`:

- buggy: PARSE event records `ret=0`, `parse_result=success`;
- fixed: the same input records `ret=-16512`, `parse_result=reject`;
- `consumed_len` / `input_len` are **null in both files** — these public
  parser APIs do not expose a consumed pointer;
- the OpenSSL `d2i_*` caller-guard behavior (success + partial consumption +
  caller-side check) is a DIFFERENT contract/migration semantic and MUST NOT
  be folded into this pair.

### 5.2 Stale-state pair — bound to the real MBEDTLS-POC-0005 reproduction

`stale_state_buggy.jsonl` / `stale_state_fixed.jsonl`,
`pair_kind: same_library_fix`:

- at the zero-length update: buggy records `len_cleared=false`; fixed
  records `len_cleared=true`;
- at the subsequent same-length reuse call: buggy records
  `sanitizer_event=signal_sigsegv` (real evidence: SIGSEGV, exit 139 — NOT
  ASan); fixed records `reused_ptr_valid=true` and no sanitizer event.

### 5.3 Lifecycle pair — bound to the real OPENSSL-ISSUE-22842 reproduction

`lifecycle_buggy.jsonl` / `lifecycle_fixed.jsonl`,
`pair_kind: same_library_fix`, `pattern_id: OPENSSL-ISSUE-22842`.

Evidence base: `knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-22842.yaml`
and `normalized_templates/openssl/evp_mac_get_size_uninit_lifecycle/`.
Root cause: `EVP_MAC_CTX_get_mac_size()` before `EVP_MAC_init` dereferences
a NULL provider algctx (SEGV on OpenSSL 3.1.1); fixed builds return 0 for
the pre-init query and 32 after HMAC-SHA256 init.

Role/state mapping for this fixture (no new `out_state` keys needed — the
size-query result is carried by `ret`):

- `EVP_MAC_fetch` → SETUP; `EVP_MAC_CTX_new` → INIT (state_after:
  `CTX_ALLOCATED`); `EVP_MAC_init` → SETUP (state_after: `MAC_INITIALIZED`);
  `EVP_MAC_CTX_get_mac_size` → QUERY; `*_free` → FREE.
- Pointer-returning calls (`fetch`, `CTX_new`) record `ret=null`,
  `out_state={}` (addresses are forbidden by the determinism rule).

`lifecycle_buggy.jsonl` (OpenSSL 3.1.1):

| seq | api | role | state_after | ret | sanitizer_event |
|---|---|---|---|---|---|
| 0 | EVP_MAC_fetch | SETUP | null | null | null |
| 1 | EVP_MAC_CTX_new | INIT | CTX_ALLOCATED | null | null |
| 2 | EVP_MAC_CTX_get_mac_size | QUERY | null (crash in-call) | null | signal_sigsegv |

The trace TERMINATES at seq 2 (attributed via the pre-call marker, §6).

`lifecycle_fixed.jsonl` (repo-validated safe build, e.g. OpenSSL 3.5.5 —
use the version string of the build M6 actually validates):

| seq | api | role | state_after | ret | sanitizer_event |
|---|---|---|---|---|---|
| 0 | EVP_MAC_fetch | SETUP | null | null | null |
| 1 | EVP_MAC_CTX_new | INIT | CTX_ALLOCATED | null | null |
| 2 | EVP_MAC_CTX_get_mac_size | QUERY | CTX_ALLOCATED | 0 | null |
| 3 | EVP_MAC_init | SETUP | MAC_INITIALIZED | 1 | null |
| 4 | EVP_MAC_CTX_get_mac_size | QUERY | MAC_INITIALIZED | 32 | null |
| 5 | EVP_MAC_CTX_free | FREE | null | null | null |
| 6 | EVP_MAC_free | FREE | null | null | null |

Expected divergence (ground truth for M2): at seq 2, a QUERY on
`CTX_ALLOCATED` — buggy fires `signal_sigsegv` with no return; fixed
returns 0 and continues. Fired rule: sanitizer/fatal-signal asymmetry.

Honesty note: the repo currently marks this pattern
`strict_reproduction: false` (local candidates only exercised post-init
success). This fixture encodes issue-report + patch semantics; M6 MUST
validate the buggy trace against a real OpenSSL 3.1.1 build before any
vulnerability claim is made downstream.

## 6. Instrumentation Notes (M6, execution layer)

- Emit a stable pre-call marker and flush it BEFORE each API call, so that
  when a crash occurs mid-call the collector can attribute the fatal signal
  to the in-flight API event (the event itself cannot self-report).
- Capture `ret`, lengths, and `out_state` immediately AFTER the call.
- Collector attributes sanitizer/signal findings to the last in-flight API.
- Existing case-level infrastructure (`runner/compile_run.py`) keeps
  stdout/stderr/returncode per case; per-API events are the new layer added
  by `contract_miner/exec/`, not a modification of runner.
