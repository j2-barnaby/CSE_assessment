#!/usr/bin/env bash
# Step 5 evidence: STIG-compliant audit logging + generic error messages.
# Run from ~/CSE_assessment/final-app with the stack running.
set -u
E=../evidence/04-remediation/step5
mkdir -p "$E"
C="curl -sk"
json() { python3 -c "import sys,json; print(json.load(sys.stdin)['$1'])"; }
out() { echo; echo "===== $1 ====="; }
alog() { docker compose exec -T flask cat /app/logs/audit.log; }
pretty() { python3 -c "
import sys,json
for l in sys.stdin:
    l=l.strip()
    if l.startswith('{'): print(json.dumps(json.loads(l)))"; }

{
out "0. BASELINE for comparison: original log format (key written in plain text)"
grep -m3 "with key" ../original-app/logs/flask_app.log 2>/dev/null || echo "(original log not present)"

out "1. Startup event recorded (ASD V-222468)"
alog | grep '"app_start"' | tail -2

out "2. Generate activity"
echo "TESTFILE-12345 step5 logging" > /tmp/s5.txt
R=$($C -F "file=@/tmp/s5.txt" https://localhost/upload)
ID=$(echo "$R" | json file_id); KEY=$(echo "$R" | json encryption_key)
echo "upload ok, file_id=$ID"
$C -o /dev/null -d "file_id=$ID" --data-urlencode "key=$KEY" https://localhost/decrypt
echo -n "wrong key  -> "; $C -d "file_id=$ID" --data-urlencode "key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" https://localhost/decrypt; echo
echo -n "bad id     -> "; $C -d "file_id=../../etc/passwd" --data-urlencode "key=$KEY" https://localhost/decrypt; echo
echo -n "no file    -> "; $C -F "wrong=@/tmp/s5.txt" https://localhost/upload; echo
echo -n "404        -> "; $C https://localhost/admin; echo
echo -n "405        -> "; $C -X DELETE https://localhost/upload; echo
head -c 11534336 /dev/zero > /tmp/s5_big.bin
echo -n "too large  -> "; $C -o /dev/null -w "HTTP %{http_code}\n" -F "file=@/tmp/s5_big.bin" https://localhost/upload
echo "spoofing attempt: X-Forwarded-For: 6.6.6.6"
$C -o /dev/null -H "X-Forwarded-For: 6.6.6.6" https://localhost/
echo "log injection attempt via filename and User-Agent"
$C -o /dev/null -A 'evil","event":"admin_login","outcome":"success' \
   -F 'file=@/tmp/s5.txt;filename=x","event":"fake_event.txt' https://localhost/upload
sleep 1

out "3. Resulting audit records (who / what / when / where / source / outcome)"
alog | tail -20 | pretty

out "4. Security events only (failures, WARNING level)"
alog | grep '"outcome": "failure"' | grep -v '"http_request"' | tail -6

out "5. Encryption key is NOT in the log (baseline: it was)"
alog | grep -c -- "$KEY" || echo "0 occurrences - key not logged"

out "6. Spoofed source IP ignored (real client IP recorded instead)"
alog | grep -c "6.6.6.6" || echo "0 occurrences - spoof ignored"
alog | tail -30 | grep -o '"src_ip": "[^"]*"' | sort | uniq -c

out "7. Log injection neutralised: every line is still exactly one valid JSON object"
alog | python3 -c "
import sys,json
lines=[l for l in sys.stdin if l.strip()]
bad=[l for l in lines if not l.startswith('{') or not isinstance(json.loads(l),dict)]
print(len(lines),'lines,',len(bad),'invalid')
print('fake admin_login events:', sum(1 for l in lines if json.loads(l).get('event')=='admin_login'))"

out "8. Same request ID in nginx log and Flask audit log (correlation)"
RID=$(alog | grep '"file_decrypt"' | grep '"success"' | tail -1 | grep -o '"request_id": "[0-9a-f]*"' | grep -o '[0-9a-f]\{32\}')
echo "request_id: $RID"
echo "-- flask:"; alog | grep "$RID" | head -2
echo "-- nginx:"; docker compose logs --no-log-prefix nginx 2>/dev/null | grep "$RID" | head -1

out "9. nginx access log: source + destination + TLS details (Web SRG V-206356)"
docker compose logs --no-log-prefix nginx 2>/dev/null | grep '"proxy_request"' | tail -2

out "10. Audit log protection (ASD V-222500/V-222501)"
docker compose exec -T flask sh -c 'ls -ln /app/logs/; ls -ldn /app/logs'
echo "nginx container cannot see the audit log:"
docker compose exec -T nginx sh -c 'ls /app/logs 2>&1 || true'

out "11. Shutdown + startup events recorded across a restart (ASD V-222468)"
docker compose restart flask >/dev/null 2>&1; sleep 6
alog | grep -E '"app_(stop|start)"' | tail -4
} 2>&1 | tee "$E/step5_results.txt"

echo; echo "Saved to $E/step5_results.txt"
