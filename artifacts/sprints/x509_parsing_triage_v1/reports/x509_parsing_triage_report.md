# x509 Parsing Triage Report

- why selected: scheduler top-1，11 个已知 seed，medium evidence，适合做路线消歧。
- x509 / DER / ASN.1: 本轮只保留 app/API 可见 x509 语义；top-level DER full-consumption 和 nested ASN.1/crash 单独路由。
- seeds found: `11`
- pure/app-level x509 seeds: `8`
- DER overlap seeds: `0`
- ASN.1 overlap seeds: `1`
- app-level candidate: `True`
- D-path crash seed: `True`
- A-path mapping potential: blocked; current family lacks comparable recipe-slot source/target oracle.
- render/run allowed: `false`
- GLM allowed: `false`
- next task: `x509_parsing_app_level_gap_triage_v1`
- confirmed vulnerability: `false`
