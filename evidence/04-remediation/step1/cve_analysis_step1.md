Grype same-day scan (original vs step 1)
Original: 51 Critical, 287 High, 334 Medium, 47 Low, 120 Negligible, 24 Unknown (863)
Step 1:   0 Critical, 78 High, 83 Medium, 17 Low, 50 Negligible, 0 Unknown (228)
Step 1 Highs: 78 rows = 24 unique CVEs; 59 rows won't-fix (Debian), 19 rows fixable = 6 OpenSSL CVEs x 3 packages + 1 zlib
Plan: apt-get upgrade + remove unneeded packages in Step 4; accept the remainder with justification
