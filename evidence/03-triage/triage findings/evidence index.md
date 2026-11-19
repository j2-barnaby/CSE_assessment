| Rank | ID | Vulnerability / finding | Severity | Updated status |
|---|---|---|---|---|
| 1 | F-01 | Weak XOR encryption using a one-byte key | **Critical** | Confirmed |
| 2 | F-02 | Encryption key disclosed in HTTP responses and application logs | **High** | Confirmed |
| 3 | F-03 | Decrypted command executed using `subprocess` and `shell=True` | **High** | Insecure code confirmed; execution not demonstrated |
| 4 | F-04 | Hardcoded API licence key in application source code | **High** | Confirmed in source; validity unverified |
| 5 | F-05 | Sensitive API_CHECK token embedded in Docker base image | **High** | Presence confirmed; validity and purpose unverified |
| 6 | F-06 | Path traversal resulting in an unintended file write | **High** | Confirmed by manual testing |
| 7 | F-07 | TLS not configured correctly on NGINX port 443 | **High** | Confirmed |
| 8 | F-08 | Telnet service exposed on port 23 | **Medium–High** | Confirmed as network exposure; out of scope |
| 9 | F-09 | Flask container running as root with limited hardening | **Medium–High** | Confirmed |
| 10 | F-10 | Vulnerable or outdated packages identified by Grype | **High–Critical** | Scanner findings require validation |
| 11 | F-11 | Potential unauthorised access due to missing authentication controls | **Medium** | Unauthenticated upload accepted; HTTP 200 returned; file creation not yet verified |
| 12 | F-12 | Potential unsafe file handling during decryption | **Medium** | Potential issue; live testing limited by disabled decryption route |
| 13 | F-13 | Potential file overwriting through duplicate filenames | **Medium** | Potential issue; overwrite not independently verified |
| 14 | F-14 | Detailed DEBUG logging and potentially sensitive error output | **Medium** | Configuration confirmed; disclosure impact partly unverified |
| 15 | F-15 | Missing NGINX security headers and version restrictions | **Low–Medium** | Configuration omission confirmed |
| 16 | F-16 | Flask service binds to all network interfaces | **Low–Medium** | Confirmed in code; external exposure not demonstrated |
| 17 | F-17 | Uploaded files are not retained after container recreation | **Low–Medium** | Confirmed persistence limitation |
