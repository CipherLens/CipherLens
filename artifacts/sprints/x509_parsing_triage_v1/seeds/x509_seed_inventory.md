# x509 Seed Inventory

- Seed 总数: `11`
- C-path app-level seeds: `7`
- D-path crash seeds: `1`
- ASN.1 overlap seeds: `1`
- needs_more_evidence: `1`

- `MBEDTLS-POC-0027`: route=`A_recipe_slot_cross_library_migration`, overlap=`app_level_x509_behavior`, input=`certificate_chain`, evidence=`strong`
- `OPENSSL-ISSUE-11567`: route=`C_app_level_validation_gap`, overlap=`app_level_x509_behavior`, input=`der_certificate`, evidence=`medium`
- `OPENSSL-ISSUE-11772`: route=`C_app_level_validation_gap`, overlap=`app_level_x509_behavior`, input=`pem_certificate`, evidence=`medium`
- `OPENSSL-ISSUE-13860`: route=`needs_more_evidence`, overlap=`needs_review`, input=`der_certificate`, evidence=`weak`
- `OPENSSL-ISSUE-14457`: route=`C_app_level_validation_gap`, overlap=`app_level_x509_behavior`, input=`certificate_chain`, evidence=`medium`
- `OPENSSL-ISSUE-14675`: route=`C_app_level_validation_gap`, overlap=`app_level_x509_behavior`, input=`certificate_chain`, evidence=`medium`
- `OPENSSL-ISSUE-23325`: route=`C_app_level_validation_gap`, overlap=`app_level_x509_behavior`, input=`crl`, evidence=`medium`
- `OPENSSL-ISSUE-29418`: route=`C_app_level_validation_gap`, overlap=`app_level_x509_behavior`, input=`pem_certificate`, evidence=`medium`
- `OPENSSL-ISSUE-29574`: route=`overlap_asn1_nested_boundary`, overlap=`overlaps_asn1_nested_boundary`, input=`der_certificate`, evidence=`medium`
- `OPENSSL-ISSUE-6788`: route=`C_app_level_validation_gap`, overlap=`app_level_x509_behavior`, input=`crl`, evidence=`medium`
- `OPENSSL-ISSUE-9043`: route=`D_crash_sanitizer_evidence_audit`, overlap=`crash_sanitizer_seed`, input=`unknown`, evidence=`medium`
