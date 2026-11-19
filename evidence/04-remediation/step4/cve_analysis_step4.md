# Step 4 CVE analysis (grype, 19 Nov 2026)

## Flask image
- High: 78 -> 77 (zlib fixed by apt-get upgrade)
- 18 remaining "fixable" rows = 6 OpenSSL CVEs x 3 packages; fix not yet published in Debian trixie-security
- Mitigation: TLS terminates in nginx, Flask has no network (network_mode: none) -> OpenSSL not on attack path
- Timeline: rebuild within 30 days of Debian release (Web SRG V-206443)

## nginx image
- Critical: 1 -> 0 (libxslt/zlib fixed by apk upgrade)
- High: 8 rows = 4 unique OpenSSL CVEs x 2 packages (libcrypto3, libssl3); no fix available
| CVE | Component | Reachable? | Reason |
| CVE-2026-95692 | AES-GCM-SIV IV | No | GCM-SIV not a TLS cipher; only AES-GCM suites enabled |
| CVE-2026-88823 | AES-GCM-SIV AAD | No | as above |
| CVE-2026-107496 | CMS encryption | No | nginx does not use CMS |
| CVE-2026-95691 | QUIC client | No | nginx is a server; QUIC/HTTP3 not enabled (grep = 0) |
- EPSS 0.3-0.4%; non-root, 0 capabilities, read-only FS limit impact
- Decision: ACCEPT, re-scan weekly, patch within 30 days of fix (Web SRG V-206443)
