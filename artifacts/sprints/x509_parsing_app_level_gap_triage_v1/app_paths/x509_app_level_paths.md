# x509 App-Level Paths

- `OPENSSL-ISSUE-11567`: app_path=`openssl x509`, observation=`prints_meaningful_output_for_malformed_input`, oracle=`malformed_accepted_with_output`
- `OPENSSL-ISSUE-11772`: app_path=`openssl x509`, observation=`verify_accepts_semantically_invalid_cert`, oracle=`verify_semantic_gap`
- `OPENSSL-ISSUE-14457`: app_path=`openssl verify`, observation=`inconsistent_reject_between_apps`, oracle=`verify_semantic_gap`
- `OPENSSL-ISSUE-14675`: app_path=`openssl verify`, observation=`verify_accepts_semantically_invalid_cert`, oracle=`verify_semantic_gap`
- `OPENSSL-ISSUE-23325`: app_path=`openssl verify`, observation=`inconsistent_reject_between_apps`, oracle=`verify_semantic_gap`
- `OPENSSL-ISSUE-29418`: app_path=`openssl x509`, observation=`inconsistent_reject_between_apps`, oracle=`inconsistent_app_behavior`
- `OPENSSL-ISSUE-6788`: app_path=`openssl crl`, observation=`inconsistent_reject_between_apps`, oracle=`inconsistent_app_behavior`
