# Advisory Evidence

## Talos / CVE Summary

- Advisory: TALOS-2017-0293
- CVE: CVE-2017-2800
- Title: WolfSSL library X.509 Certificate Text Parsing Code Execution Vulnerability
- Discovered by: Aleksandar Nikolic of Cisco Talos
- Public disclosure date: 2017-05-08
- Exploit-DB entry: 41984

## Root Cause Summary

The vulnerability is related to the X.509 certificate text parsing code. Talos describes it as affecting parsing of DER certificate string fields, including:

- commonName
- countryName
- localityName
- stateName
- orgName
- orgUnit

A crafted X.509 certificate can trigger a single out-of-bounds byte overwrite.

## Expected Trigger

The attacker supplies a malicious X.509 certificate to either a server or client application using wolfSSL.

## Expected Vulnerable Version

- wolfSSL 3.10.2
