# MAC lifecycle state-machine misuse impact assessment

## Goal

This impact demo evaluates whether the observed MAC lifecycle divergence can affect application-level state-machine misuse detection.

The tested misuse pattern is:

    update("authorized-prefix")
    final/finish(tag_prefix)
    update("post-finish-data")
    final/finish(tag_after_post_finish)

The application model assumes that a MAC operation should be closed after final/finish. If post-finish update fails, the application rejects the data. If post-finish update succeeds, the application continues and accepts the path.

## OpenSSL result

For both AES-128-CBC CMAC and AES-256-CBC CMAC, OpenSSL accepted post-final update and produced a new tag after another finalization.

Observed decision:

    application_decision=APPLICATION_ACCEPTED_POST_FINISH_DATA

This means that, under the tested application-state-machine model, OpenSSL does not reject the post-final misuse. The application continues execution and accepts the post-finish data path.

## mbedTLS PSA result

For both AES-128-CBC CMAC and AES-256-CBC CMAC, mbedTLS PSA rejected post-finish update and post-finish finalization with:

    -137

This corresponds to `PSA_ERROR_BAD_STATE` in the existing triage interpretation.

Observed decision:

    application_decision=APPLICATION_REJECT

This means that the same application-state-machine misuse is caught by the stricter PSA operation lifecycle.

## Prefix tag consistency

The prefix MAC tags match between OpenSSL and mbedTLS PSA before the misuse point:

AES-128-CBC:

    5ff09966d566aa30be83275892935e72

AES-256-CBC:

    264e3b7082ba181a21bb7cf6a79c2b70

This indicates that the two implementations agree on the normal prefix MAC computation. The behavioral divergence occurs after final/finish, when the application attempts to continue updating the MAC operation.

## Security interpretation

This demo does not show a direct CMAC cryptographic failure. It does not prove MAC forgery, memory corruption, or a confirmed authentication bypass.

It does show that a strict-lifecycle application assumption can lead to different application-level decisions across libraries:

- mbedTLS PSA fails closed by rejecting post-finish update/final paths.
- OpenSSL CMAC allows the post-final path to continue and produces a new tag.

Therefore, the result supports classifying this issue as:

- state-machine misuse detection gap;
- MAC lifecycle semantic divergence;
- migration-risk candidate;
- documentation-ambiguity candidate for OpenSSL EVP_MAC CMAC finalization behavior.

The main security-relevant concern is that applications migrated from a strict PSA-style MAC lifecycle to OpenSSL EVP_MAC CMAC may lose misuse detection if they rely on the library to reject post-finish operations.
