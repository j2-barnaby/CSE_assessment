#!/usr/bin/env bash
# STEP 7 - external retest from the ATTACKER VM (the machine used for Part 1).
# Uses the same tools and flags as evidence/02-vulnerability_findings/2.7NandW-testing
# so the before/after comparison is like-for-like.
#   Usage:  ./retest_remote.sh <app-vm-ip>      e.g. ./retest_remote.sh 192.168.12.160
# Copy the resulting folder back into evidence/05-retest/2.7-network/ in the repo.
set -u
T=${1:?usage: $0 <app-vm-ip>}
O=retest_remote_$(date +%Y%m%d_%H%M)
mkdir -p "$O"; cd "$O"
WL=/usr/share/wordlists/dirb/common.txt
hr() { echo; echo "=================== $1 ==================="; }
have() { command -v "$1" >/dev/null || { echo "(skipped: $1 not installed)"; return 1; }; }

{
hr "Tool versions"
for t in nmap sslscan gobuster ffuf openssl curl; do printf "%-9s " "$t"; ($t --version 2>/dev/null || $t version 2>/dev/null || $t -V 2>/dev/null) | head -1; done

hr "1. Full TCP port + service scan (before: 22 ssh, 23 telnet, 443 'http nginx 1.31.8')"
have nmap && sudo nmap --privileged -sTV -p- -oN nmap_after.txt "$T" | grep -E "^[0-9]+/tcp|Nmap done"

hr "2. TLS cipher enumeration (before: no TLS at all on 443)"
have nmap && sudo nmap --privileged --script ssl-enum-ciphers -p 443 -oN tls_nmap_after.txt "$T" | grep -E "TLSv|TLS_|least strength|443"

hr "3. sslscan (before: every protocol 'disabled', certificate unparseable)"
have sslscan && sslscan --no-colour "$T" > sslscan_after.txt 2>&1 && \
  sed -n '/SSL\/TLS Protocols/,/Heartbleed/p;/Supported Server Cipher/,/Server Key Exchange/p;/Subject:/p;/Issuer:/p;/Signature Algorithm/p' sslscan_after.txt

hr "4. Explicit protocol tests (before: TLS 1.2/1.3 handshakes failed - plain HTTP)"
for v in tls1 tls1_1 tls1_2 tls1_3; do
  echo | timeout 6 openssl s_client -connect "$T:443" -$v > "tls_${v}_after.txt" 2>&1
  printf "%-8s %s\n" "$v" "$(grep -oE 'Cipher is [^ ]+' "tls_${v}_after.txt" | head -1 || true)"
done
echo | timeout 6 openssl s_client -connect "$T:443" -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 | grep -oE "Cipher is [^ ]+" | sed 's/^/ChaCha20 (not NIST) -> /'

hr "5. HTTP vs HTTPS behaviour (before: HTTP served on 443, port 80 closed)"
curl -s  -o /dev/null -w "http://$T/            -> %{http_code} %{redirect_url}\n" "http://$T/"
curl -s  -o /dev/null -w "http://$T:443/        -> %{http_code}\n" "http://$T:443/"
curl -sk -o /dev/null -w "https://$T/           -> %{http_code} %{redirect_url}\n" "https://$T/"
curl -s --max-time 4 -o /dev/null "http://$T:5000/" && echo "port 5000 -> REACHABLE" || echo "port 5000 -> blocked"
curl -skI "https://$T/login" | grep -iE "^(HTTP|server|strict|content-security|x-frame|x-content|referrer|set-cookie)" | tee headers_after.txt

hr "6. Directory brute force - gobuster (before: /upload 405 reachable anonymously)"
have gobuster && [ -f "$WL" ] && gobuster dir -q -k -u "https://$T" -w "$WL" -o gobuster_after.txt --no-color 2>/dev/null; cat gobuster_after.txt 2>/dev/null

hr "7. Directory brute force - ffuf (same wordlist as ffuf_before.json)"
have ffuf && [ -f "$WL" ] && ffuf -s -u "https://$T/FUZZ" -w "$WL" -o ffuf_final.json -of json >/dev/null 2>&1
[ -f ffuf_final.json ] && python3 -c "
import json; d=json.load(open('ffuf_final.json'))
for r in d['results']: print(f\"/{r['input']['FUZZ']:<12} {r['status']}  -> {r.get('redirectlocation','')}\")"

hr "8. Rate limiting seen from outside (brute-force throttling)"
for i in $(seq 15); do curl -sk -o /dev/null -w "%{http_code} " -d "username=x&password=y" "https://$T/login"; done; echo
} 2>&1 | tee remote_retest_summary.txt

echo; echo "Saved in $(pwd). Copy this folder into evidence/05-retest/2.7-network/ in the repo."
