# CVE Evidence

- CVE: CVE-2017-2800
- Talos ID: TALOS-2017-0293
- Exploit-DB ID: 41984
- Affected library: wolfSSL
- Affected versions: wolfSSL through 3.10.2
- Tested vulnerable version: wolfSSL 3.10.2
- Vulnerability class: X.509 certificate text parsing off-by-one / out-of-bounds byte overwrite
- Trigger condition: a specially crafted X.509 certificate supplied to a server or client application using wolfSSL
- Expected impact: certificate validation issues, denial of service, and possible remote code execution

## References

- https://talosintelligence.com/vulnerability_reports/TALOS-2017-0293
- https://blog.talosintelligence.com/wolfssl-x509-vuln/
- https://www.exploit-db.com/exploits/41984/
- https://nvd.nist.gov/vuln/detail/CVE-2017-2800
