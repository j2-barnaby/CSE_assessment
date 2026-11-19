#!/usr/bin/env bash
# STEP 7 - full retest of the FINAL application, run on the app VM.
# Repeats the Part 1 investigation (evidence/02-vulnerability_findings) with the
# same inputs so every "before" result has a matching "after".
#   Usage:  ./retest_local.sh            (from ~/CSE_assessment/final-app)
#           RUN_ZAP=1 ./retest_local.sh  (also runs an OWASP ZAP baseline scan, ~2 GB image)
set -u
E=../evidence/05-retest
BEFORE=../evidence/02-vulnerability_findings
mkdir -p "$E"/{2.1-code,2.2-infra,2.3-bandit,2.4-image,2.6-grype,2.7-network,2.8-manual,2.9-traffic,3.0-auth}
B=https://localhost
W=$(mktemp -d)
PW='Retest-Harbour-Lantern-63!'
JAR="$W/retest.jar"
hr() { echo; echo "=================== $1 ==================="; }
token() { curl -sk -b "$JAR" -c "$JAR" "$B$1" | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | cut -d'"' -f4; }
grype() { docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$@" 2>/dev/null; }
sev() { python3 -c "
import json,sys,collections
d=json.load(open('$1')); m=d['matches']
rows=collections.Counter(x['vulnerability']['severity'] for x in m)
uniq=collections.Counter()
seen=set()
for x in m:
    k=x['vulnerability']['id']
    if k not in seen: seen.add(k); uniq[x['vulnerability']['severity']]+=1
order=['Critical','High','Medium','Low','Negligible','Unknown']
print('  rows  :', ', '.join(f'{s} {rows.get(s,0)}' for s in order), '| total', len(m))
print('  unique:', ', '.join(f'{s} {uniq.get(s,0)}' for s in order), '| total', len(seen))
fix=sum(1 for x in m if x['vulnerability']['severity'] in ('Critical','High') and x['vulnerability'].get('fix',{}).get('state')=='fixed')
print('  Critical/High rows with a fix available:', fix)"; }

echo "Retest started $(date -u '+%Y-%m-%d %H:%M UTC') on $(hostname)"
echo "Results folder: $E"

# ---------------------------------------------------------------------------
hr "2.1 Code review: dangerous patterns (before vs after)"
{
  for f in ../original-app/flask_app.py flask_app.py; do
    echo "--- $f"
    echo -n "subprocess / shell=True : "; grep -cE "subprocess|shell=True" "$f"
    echo -n "hard-coded key          : "; grep -cE "API_LICENCE_KEY *=" "$f"
    echo -n "XOR 'encryption'        : "; grep -cE "b \^ key" "$f"
    echo -n "writes to /tmp          : "; grep -cE "'/tmp'" "$f"
    echo -n "key written to log      : "; grep -cE "with key \{key\}" "$f"
    echo -n "DEBUG log level         : "; grep -cE "level=logging.DEBUG" "$f"
    echo -n "AES-GCM                 : "; grep -c "AESGCM(" "$f"
    echo -n "parameterised SQL (?)   : "; grep -cE "VALUES \(\?|= \?" "$f"
  done
} 2>&1 | tee "$E/2.1-code/code_patterns_before_after.txt"

# ---------------------------------------------------------------------------
hr "2.2 Infrastructure: ports, users, hardening"
{
  echo "--- host listening ports (compare 2.7 ss-portidentification.txt)"
  ss -tlnp 2>/dev/null | grep -E ":(22|23|80|443|5000|8080|8443) " || ss -tln
  echo; echo "--- containers"
  docker compose ps
  for c in final-app-flask-1 final-app-nginx-1; do
    echo; echo "--- $c"
    docker inspect -f 'User={{.Config.User}} ReadOnlyRootfs={{.HostConfig.ReadonlyRootfs}} CapDrop={{.HostConfig.CapDrop}} SecurityOpt={{.HostConfig.SecurityOpt}} Privileged={{.HostConfig.Privileged}} NetworkMode={{.HostConfig.NetworkMode}} PidsLimit={{.HostConfig.PidsLimit}} MemoryBytes={{.HostConfig.Memory}} Restart={{.HostConfig.RestartPolicy.Name}}' "$c"
    docker inspect -f 'Published ports: {{range $p,$b := .NetworkSettings.Ports}}{{$p}}->{{range $b}}{{.HostPort}} {{end}}{{end}}' "$c"
    docker inspect -f 'Env: {{range .Config.Env}}{{.}} | {{end}}' "$c"
  done
  echo; echo "--- process users inside containers"
  docker compose exec -T flask id; docker compose exec -T nginx id
  echo; echo "--- TLS key permissions on host"
  ls -ln certs/
} 2>&1 | tee "$E/2.2-infra/infrastructure_after.txt"

# ---------------------------------------------------------------------------
hr "2.3 Bandit static analysis (before vs after)"
{
  for f in original-app/flask_app.py final-app/flask_app.py; do
    echo "--- $f"
    docker run --rm -v "$(cd .. && pwd)":/src:ro python:3.13-slim sh -c \
      "pip install -q bandit 2>/dev/null && bandit -q /src/$f" 2>&1 | grep -E "Issue|Severity|Location|No issues|Total" || echo "No issues identified."
  done
} 2>&1 | tee "$E/2.3-bandit/bandit_before_after.txt"

# ---------------------------------------------------------------------------
hr "2.4 Image inspection: backdoor and secrets"
{
  echo "--- base image of final flask image"
  docker history --no-trunc --format '{{.CreatedBy}}' final-app-flask:latest | tail -3 | cut -c1-160
  echo; echo "--- environment baked into the image"
  docker inspect -f '{{range .Config.Env}}{{.}}{{"\n"}}{{end}}' final-app-flask:latest
  echo "--- search the whole image filesystem for the API_CHECK payload / canarytokens URL"
  docker run --rm --network none --entrypoint sh final-app-flask:latest -c \
    'grep -rIl -e API_CHECK -e canarytokens /root /home /etc /app /opt /usr/local/bin 2>/dev/null || echo "none found"'
  echo "--- /etc/environment and root bashrc"
  docker run --rm --network none --entrypoint sh final-app-flask:latest -c \
    'cat /etc/environment 2>/dev/null; tail -3 /root/.bashrc 2>/dev/null; true'
} 2>&1 | tee "$E/2.4-image/image_inspection_after.txt"

# ---------------------------------------------------------------------------
hr "2.6 Grype CVE scans, same day for a fair comparison"
docker image inspect original-app-flask:latest >/dev/null 2>&1 || (cd ../original-app && docker compose build flask >/dev/null 2>&1)
grype original-app-flask:latest -o json > "$E/2.6-grype/grype_original_flask.json"
grype nginx:alpine              -o json > "$E/2.6-grype/grype_original_nginx.json"
grype final-app-flask:latest    -o json > "$E/2.6-grype/grype_final_flask.json"
grype final-app-nginx:latest    -o json > "$E/2.6-grype/grype_final_nginx.json"
{
  for f in original_flask final_flask original_nginx final_nginx; do
    echo "--- $f"; sev "$E/2.6-grype/grype_$f.json"
  done
} 2>&1 | tee "$E/2.6-grype/grype_summary.txt"

# ---------------------------------------------------------------------------
hr "2.7 Local network checks (full set from the attacker VM via retest_remote.sh)"
{
  echo "--- HTTP behaviour (baseline: HTTP served on 443, port 80 closed)"
  curl -s -o /dev/null -w "http://localhost/          -> %{http_code} %{redirect_url}\n" http://localhost/
  curl -s -o /dev/null -w "http://localhost:443/      -> %{http_code}\n" http://localhost:443/
  curl -sk -o /dev/null -w "https://localhost/         -> %{http_code} %{redirect_url}\n" https://localhost/
  curl -s --max-time 4 -o /dev/null http://172.23.0.2:5000/ && echo "direct Flask 172.23.0.2:5000 -> REACHABLE" || echo "direct Flask 172.23.0.2:5000 -> blocked"
  echo; echo "--- response headers"
  curl -skI https://localhost/login | grep -iE "^(HTTP|server|strict|content-security|x-frame|x-content|referrer|permissions|set-cookie)"
  echo; echo "--- TLS protocol + cipher matrix"
  for o in "-tls1" "-tls1_1" "-tls1_2" "-tls1_3"; do
    printf "%-9s " "$o"; echo | timeout 5 openssl s_client -connect localhost:443 $o 2>/dev/null | grep -oE "Cipher is [^ ]+" | head -1 || true; echo
  done
  if command -v nmap >/dev/null; then
    echo "--- nmap -sV -p- localhost"; nmap -sV -p- localhost 2>/dev/null | grep -E "^[0-9]+/tcp|Nmap done"
    echo "--- nmap ssl-enum-ciphers"; nmap --script ssl-enum-ciphers -p 443 localhost 2>/dev/null | grep -E "TLSv|TLS_|least strength"
  fi
} 2>&1 | tee "$E/2.7-network/network_local_after.txt"

# ---------------------------------------------------------------------------
hr "3.0 / F-11 Authentication test (baseline: anonymous upload returned a key)"
echo "F11 authentication test" > "$W/f11_test.txt"
curl -sk -i -H "Accept: application/json" -F "file=@$W/f11_test.txt" $B/upload 2>&1 | grep -E "^HTTP|error" \
  | tee "$E/3.0-auth/f11_test_result_after.txt"

# ---------------------------------------------------------------------------
hr "2.8 Manual tests repeated with the same inputs (authenticated, over HTTPS)"
t=$(token /register)
curl -sk -b "$JAR" -c "$JAR" -o /dev/null --data-urlencode "csrf_token=$t" --data-urlencode "username=retester" \
  --data-urlencode "password=$PW" --data-urlencode "confirm=$PW" $B/register
sleep 2; t=$(token /login)
curl -sk -b "$JAR" -c "$JAR" -o /dev/null -w "login as retester -> %{http_code}\n" --data-urlencode "csrf_token=$t" \
  --data-urlencode "username=retester" --data-urlencode "password=$PW" $B/login
CSRF=$(token /)
up() {  # $1 = output name, rest = curl -F args
  local name=$1; shift
  curl -sk -b "$JAR" -H "Accept: application/json" -H "X-CSRF-Token: $CSRF" -w "\nHTTP %{http_code}\n" "$@" $B/upload \
    > "$E/2.8-manual/${name}_after.txt" 2>&1
  printf "%-18s %s\n" "$name" "$(tr '\n' ' ' < "$E/2.8-manual/${name}_after.txt" | cut -c1-170)"
}
cp $BEFORE/2.8-manual_testing/normal.txt "$W/normal.txt" 2>/dev/null || echo "TESTFILE-12345 normal" > "$W/normal.txt"
: > "$W/empty.txt"
echo "special" > "$W/special.txt"
echo "long"    > "$W/long.txt"
head -c 52428800 /dev/urandom > "$W/big.bin"   # 50 MB, same as the baseline test
{
  up key_response     -F "file=@$W/normal.txt"
  up duplicate_first  -F "file=@$W/normal.txt"
  up duplicate_second -F "file=@$W/normal.txt"
  up empty_file       -F "file=@$W/empty.txt"
  up incorrect_field  -F "wrongfield=@$W/normal.txt"
  up missing_file     -X POST
  up special_filename -F "file=@$W/special.txt;filename=test file_!@#\$.txt"
  up traversal        -F "file=@$W/normal.txt;filename=../../../../etc/passwd"
  up long_filename    -F "file=@$W/long.txt;filename=$(python3 -c "print('A'*300+'.txt')")"
  up large_file       -F "file=@$W/big.bin"
  echo
  echo "Duplicate uploads stored separately (different file_id):"
  grep -ho '"file_id":"[0-9a-f]*"' "$E"/2.8-manual/duplicate_*_after.txt
  echo
  echo "--- XOR brute force (baseline xor_test.py recovered the key) against the NEW ciphertext"
  ID=$(grep -o '"file_id":"[0-9a-f]*"' "$E/2.8-manual/key_response_after.txt" | cut -d'"' -f4)
  docker compose exec -T flask cat "/data/$ID.enc" > "$E/2.8-manual/stored_AES_file.enc"
  python3 - "$E/2.8-manual/stored_AES_file.enc" "$W/normal.txt" <<'PY'
import sys
cipher = open(sys.argv[1], 'rb').read(); plain = open(sys.argv[2], 'rb').read()
hits = [k for k in range(256) if bytes(b ^ k for b in cipher[12:12+len(plain)]) == plain]
print("XOR keys that decrypt the file:", hits or "none - brute force fails")
print(f"plaintext {len(plain)} bytes -> stored {len(cipher)} bytes (12-byte nonce + ciphertext + 16-byte GCM tag)")
PY
} 2>&1 | tee "$E/2.8-manual/manual_tests_summary_after.txt"

# ---------------------------------------------------------------------------
hr "2.9 Traffic capture: is file content visible on the network? (baseline pcap: yes)"
{
  SECRET="PCAP-SECRET-$(date +%s)"
  echo "$SECRET confidential" > "$W/pcap_secret.txt"
  sudo -n true 2>/dev/null || echo "(sudo will ask for your password for tcpdump)"
  sudo tcpdump -i any -U -w "$E/2.9-traffic/after_network_traffic.pcap" 'tcp port 443 or tcp port 8443 or tcp port 80 or tcp port 8080' >/dev/null 2>&1 &
  TCPD=$!; sleep 3
  curl -sk -b "$JAR" -H "Accept: application/json" -H "X-CSRF-Token: $CSRF" -F "file=@$W/pcap_secret.txt" $B/upload >/dev/null
  curl -s -o /dev/null http://localhost/upload
  sleep 2; sudo kill $TCPD 2>/dev/null; sleep 1
  sudo chown "$(id -u):$(id -g)" "$E/2.9-traffic/after_network_traffic.pcap" 2>/dev/null
  echo "packets captured: $(tcpdump -r "$E/2.9-traffic/after_network_traffic.pcap" 2>/dev/null | wc -l)"
  echo -n "secret text visible in AFTER capture : "; grep -ac "$SECRET" "$E/2.9-traffic/after_network_traffic.pcap" || true
  echo -n "packets on HTTPS port (encrypted)    : "; tcpdump -r "$E/2.9-traffic/after_network_traffic.pcap" 'tcp port 8443 or tcp port 443' 2>/dev/null | wc -l
  if [ -f "$BEFORE/2.9-network-testing/before_network_traffic.pcapng" ]; then
    echo -n "TESTFILE text visible in BEFORE capture: "; grep -ac "TESTFILE" "$BEFORE/2.9-network-testing/before_network_traffic.pcapng" || true
  fi
} 2>&1 | tee "$E/2.9-traffic/traffic_after.txt"

# ---------------------------------------------------------------------------
if [ "${RUN_ZAP:-0}" = "1" ]; then
  hr "OWASP ZAP baseline scan (compare 2.7 02-ZAP.png)"
  Z="$W/zap"; mkdir -p "$Z"; chmod 777 "$Z"
  docker run --rm --network host -v "$Z":/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py -t https://localhost/login -r zap_after.html -J zap_after.json -I 2>&1 | tail -25 \
    | tee "$E/2.7-network/zap_after_summary.txt"
  cp "$Z"/zap_after.* "$E/2.7-network/" 2>/dev/null
fi

rm -rf "$W"
hr "DONE"
echo "Everything saved under $E. Next: run retest_remote.sh from the attacker VM."
