# libdkim++ Public-Key Caller Audit Acceptance

## Target

- Project: halon/libdkimpp
- Commit: 9defa162eebc644b006b7a51e92162640a810ee9
- Component: DKIM::PublicKey::Parse
- Target API: d2i_PUBKEY
- Backend: OpenSSL 3.5.5
- Source pattern: top-level DER trailing data

## Production path

DKIM DNS TXT p= field
→ Base64 decoding
→ PublicKey::Parse
→ d2i_PUBKEY
→ RSA public key
→ DKIM signature verification

## Baseline

- Canonical SPKI accepted
- Tail 0500 accepted
- Tail 3000 accepted
- Tail 020100 accepted
- Canonical round-trip preserved
- Public-key identity preserved
- Signature verification preserved
- No ASan or UBSan finding

## Fix control

- Canonical SPKI still accepted
- Tail 0500 rejected
- Tail 3000 rejected
- Tail 020100 rejected
- Fix checks that d2i_PUBKEY consumes the entire decoded input

## Verdict

- Caller behavior: confirmed
- Fix control: confirmed
- Production path: confirmed
- External protocol input boundary: confirmed
- Concrete security impact: unproven
- Vulnerability: not confirmed
- Final classification: production_reachable_candidate
