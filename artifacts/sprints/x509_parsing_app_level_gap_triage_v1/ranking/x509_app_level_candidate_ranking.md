# x509 App-Level Candidate Ranking

- top-1: `OPENSSL-ISSUE-14457`
- top-2: `OPENSSL-ISSUE-29418`
- top-3: `OPENSSL-ISSUE-14675`

- rank 1 `OPENSSL-ISSUE-14457`: score=`11`, status=`needs_input_recovery`, input=`synthetic_only`, oracle=`verify_semantic_gap`
- rank 2 `OPENSSL-ISSUE-29418`: score=`10`, status=`needs_input_recovery`, input=`placeholder_only`, oracle=`inconsistent_app_behavior`
- rank 3 `OPENSSL-ISSUE-14675`: score=`9`, status=`needs_input_recovery`, input=`placeholder_only`, oracle=`verify_semantic_gap`
- rank 4 `OPENSSL-ISSUE-23325`: score=`8`, status=`needs_input_recovery`, input=`synthetic_only`, oracle=`verify_semantic_gap`
- rank 5 `OPENSSL-ISSUE-11772`: score=`8`, status=`needs_input_recovery`, input=`placeholder_only`, oracle=`verify_semantic_gap`
- rank 6 `OPENSSL-ISSUE-11567`: score=`6`, status=`needs_input_recovery`, input=`placeholder_only`, oracle=`malformed_accepted_with_output`
- rank 7 `OPENSSL-ISSUE-6788`: score=`5`, status=`needs_input_recovery`, input=`synthetic_only`, oracle=`inconsistent_app_behavior`
