#!/usr/bin/env bash
# Step 3 evidence: TLS (NIST SP 800-52r2), HTTPS-only, Flask not directly reachable.
# Run from ~/CSE_assessment/final-app with the stack running.
set -u
E=../evidence/04-remediation/step3
mkdir -p "$E"
CA="--cacert certs/nginx.crt"   # verify against our cert instead of using -k
json() { python3 -c "import sys,json; print(json.load(sys.stdin)['$1'])"; }
out() { echo; echo "===== $1 ====="; }
tls() {  # $1 = label, rest = openssl s_client options
  local label=$1; shift
  local r
  r=$(echo | timeout 5 openssl s_client -connect localhost:443 "$@" 2>&1 | grep -oE "Cipher is [^ ]+" | head -1)
  if [ -z "$r" ] || [ "$r" = "Cipher is (NONE)" ]; then r="REJECTED"; fi
  printf "%-45s %s\n" "$label" "$r"
}

{
out "1. Containers and published ports"
docker compose ps

out "2. HTTP (port 80) redirects to HTTPS"
curl -s -o /dev/null -w "HTTP %{http_code} -> %{redirect_url}\n" http://localhost/
curl -s -o /dev/null -w "HTTP %{http_code} -> %{redirect_url}\n" http://localhost/upload

out "3. Plain HTTP sent to port 443 is refused (baseline returned 200 OK here)"
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:443/

out "4. HTTPS works with certificate verification + security headers"
curl -s $CA -I https://localhost/ | grep -iE "^HTTP|^server:|strict-transport|content-security|x-frame|x-content-type|referrer"

out "5. Protocol versions (only TLS 1.2 and 1.3 allowed)"
tls "SSLv3"   -ssl3
tls "TLS 1.0" -tls1
tls "TLS 1.1" -tls1_1
tls "TLS 1.2" -tls1_2
tls "TLS 1.3" -tls1_3

out "6. Cipher suites: NIST 800-52r2 accepted, everything else rejected"
tls "TLS1.3 AES_256_GCM_SHA384 (NIST)"     -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384
tls "TLS1.3 AES_128_GCM_SHA256 (NIST)"     -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256
tls "TLS1.3 CHACHA20_POLY1305 (not NIST)"  -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256
tls "TLS1.2 ECDHE-ECDSA-AES256-GCM (NIST)" -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384
tls "TLS1.2 ECDHE-ECDSA-AES128-GCM (NIST)" -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256
tls "TLS1.2 ECDHE-ECDSA-AES256-SHA384 (CBC)" -tls1_2 -cipher ECDHE-ECDSA-AES256-SHA384
tls "TLS1.2 AES256-SHA (no forward secrecy)" -tls1_2 -cipher AES256-SHA
tls "TLS1.2 ECDHE-ECDSA-CHACHA20 (not NIST)" -tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305
tls "TLS1.2 DES-CBC3-SHA (3DES)"           -tls1_2 -cipher DES-CBC3-SHA

out "7. Certificate details"
openssl x509 -in certs/nginx.crt -noout -subject -issuer -dates -ext subjectAltName
openssl x509 -in certs/nginx.crt -noout -text | grep -E "Public Key Algorithm|NIST CURVE|Signature Algorithm" | sort -u

out "8. Flask cannot be reached directly (baseline: http://172.23.0.2:5000 worked)"
echo "Flask network mode: $(docker inspect -f '{{.HostConfig.NetworkMode}}' final-app-flask-1)"
FIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' final-app-flask-1 | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | xargs)
echo "Flask container IP(s): ${FIP:-NONE - no network interface}"
docker compose exec -T flask python -c "import socket; print('interfaces:', [n for _, n in socket.if_nameindex()])"
docker compose exec -T flask sh -c "ls -l /run/app/"
echo "Retry the baseline address directly:"
curl -s --max-time 4 -o /dev/null http://172.23.0.2:5000/ && echo "172.23.0.2:5000 reachable!" || echo "http://172.23.0.2:5000 -> connection FAILED (blocked)"
for ip in $FIP; do
  curl -s --max-time 4 -o /dev/null -w "http://$ip:5000 -> HTTP %{http_code}\n" "http://$ip:5000/" \
    || echo "http://$ip:5000 -> connection FAILED (blocked)"
done
curl -s --max-time 4 -o /dev/null http://localhost:5000/ && echo "localhost:5000 reachable!" || echo "localhost:5000 -> connection FAILED (blocked)"

out "9. Flask has no outbound internet (internal network) - would have stopped the exfiltration"
docker compose exec -T flask python -c "
import socket
try:
    socket.create_connection(('canarytokens.com', 80), timeout=4); print('OUTBOUND ALLOWED')
except Exception as e:
    print('outbound blocked:', type(e).__name__)"

out "10. Functional round trip over HTTPS"
echo "TESTFILE-12345 step3 over TLS" > /tmp/s3_plain.txt
R=$(curl -s $CA -F "file=@/tmp/s3_plain.txt" https://localhost/upload); echo "$R"
ID=$(echo "$R" | json file_id); KEY=$(echo "$R" | json encryption_key)
curl -s $CA -o /tmp/s3_decrypted.txt -d "file_id=$ID" --data-urlencode "key=$KEY" https://localhost/decrypt
sha256sum /tmp/s3_plain.txt /tmp/s3_decrypted.txt

out "11. nmap TLS cipher enumeration (compare with tls_nmap_before.txt)"
if command -v nmap >/dev/null; then nmap -sV --script ssl-enum-ciphers -p 80,443 localhost; else echo "nmap not installed"; fi
} 2>&1 | tee "$E/step3_results.txt"

echo; echo "Saved to $E/step3_results.txt"
