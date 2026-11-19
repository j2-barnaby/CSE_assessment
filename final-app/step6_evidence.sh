#!/usr/bin/env bash
# Step 6 evidence: authentication, sessions, CSRF, per-user access control.
# Run from ~/CSE_assessment/final-app with the stack running.
set -u
E=../evidence/04-remediation/step6
mkdir -p "$E"
B=https://localhost
W=$(mktemp -d)
PA='Quartz-Lantern-Harbour-47!'
PB='Copper-Meadow-Violin-82?'
out() { echo; echo "===== $1 ====="; }
jar() { echo "$W/$1.jar"; }
token() {  # $1 jar, $2 path
  curl -sk -b "$(jar $1)" -c "$(jar $1)" "$B$2" | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | cut -d'"' -f4
}
register() {  # $1 jar $2 user $3 pass
  local t; t=$(token $1 /register); sleep 3
  curl -sk -b "$(jar $1)" -c "$(jar $1)" -o "$W/reg.html" -w "%{http_code}" \
    --data-urlencode "csrf_token=$t" --data-urlencode "username=$2" \
    --data-urlencode "password=$3" --data-urlencode "confirm=$3" "$B/register"
}
login() {  # $1 jar $2 user $3 pass
  local t; t=$(token $1 /login); sleep 3
  curl -sk -b "$(jar $1)" -c "$(jar $1)" -o /dev/null -w "%{http_code}" \
    --data-urlencode "csrf_token=$t" --data-urlencode "username=$2" \
    --data-urlencode "password=$3" "$B/login"
}
api() {  # $1 jar, rest = curl args (JSON responses)
  local j=$1; shift
  local t; t=$(token $j /)
  curl -sk -b "$(jar $j)" -c "$(jar $j)" -H "Accept: application/json" -H "X-CSRF-Token: $t" "$@"
}
alog() { docker compose exec -T flask cat /app/logs/audit.log; }
db() { docker compose exec -T flask python -c "import sqlite3; c=sqlite3.connect('/data/files.db'); $1"; }

{
out "0. Fresh start: no users yet"
db "print('users in database:', c.execute('select count(*) from users').fetchone()[0])"

out "1. Unauthenticated access is refused (baseline: anyone could upload)"
echo "(upload with no session is rejected before it reaches the app logic)"
curl -sk -o /dev/null -w "GET /        -> HTTP %{http_code} -> %{redirect_url}\n" $B/
curl -sk -H "Accept: application/json" -F "file=@/etc/hostname" $B/upload; echo

out "2. Password policy enforced (ASD V-222536 to V-222540)"
echo -n "weak password 'password123' -> HTTP $(register anon alice password123)  "
grep -o 'Password must have[^<]*' "$W/reg.html" | head -1

out "3. Register two users"
echo "alice -> HTTP $(register a alice "$PA")"
echo "bob   -> HTTP $(register b bob "$PB")"

out "4. Passwords stored only as salted PBKDF2-SHA256 hashes (ASD V-222542)"
db "[print(u, h[:45]+'...') for u,h in c.execute('select username,password_hash from users')]"

out "5. Login without a CSRF token is rejected (ASD V-222603)"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" -d "username=alice&password=x" $B/login

out "6. Login + hardened session cookie (ASD V-222575, V-222576, V-222579)"
echo "alice login -> HTTP $(login a alice "$PA")"
t=$(token c /login); sleep 3
curl -sk -c "$(jar c)" -b "$(jar c)" -D - -o /dev/null --data-urlencode "csrf_token=$t" \
  --data-urlencode "username=alice" --data-urlencode "password=$PA" $B/login | grep -i "^set-cookie"

out "7. Alice uploads and decrypts her own file"
echo "TESTFILE-12345 alice private data" > /tmp/s6_alice.txt
R=$(api a -F "file=@/tmp/s6_alice.txt" $B/upload); echo "$R"
ID=$(echo "$R" | python3 -c "import sys,json;print(json.load(sys.stdin)['file_id'])")
KEY=$(echo "$R" | python3 -c "import sys,json;print(json.load(sys.stdin)['encryption_key'])")
api a -o /tmp/s6_alice_out.txt -d "file_id=$ID" --data-urlencode "key=$KEY" $B/decrypt
sha256sum /tmp/s6_alice.txt /tmp/s6_alice_out.txt

out "8. Bob cannot see, decrypt or delete Alice's file - even WITH her key (ASD V-222425)"
echo "bob login -> HTTP $(login b bob "$PB")"
curl -sk -b "$(jar b)" $B/ | grep -c "s6_alice.txt" | sed 's/^/alice file visible in bob list: /'
echo -n "bob decrypt (correct key) -> "; api b -d "file_id=$ID" --data-urlencode "key=$KEY" $B/decrypt; echo
echo -n "bob delete               -> "; api b -d "file_id=$ID" $B/delete; echo
db "print('alice file still in database:', c.execute('select count(*) from files where id=?',('$ID',)).fetchone()[0]==1)"

out "9. Cross-site scripting: malicious filename is neutralised (ASD V-222602)"
echo x > /tmp/s6_x.txt
api a -F "file=@/tmp/s6_x.txt;filename=<script>alert(1)</script>.txt" $B/upload | grep -o '"filename":"[^"]*"'
curl -sk -b "$(jar a)" $B/ | grep -c "<script>alert" | sed 's/^/raw <script> tags in page: /'

out "10. Account lockout after 3 failures in 15 minutes (ASD V-222432)"
for i in 1 2 3; do echo "bob wrong password #$i -> HTTP $(login x bob WrongPassword$i)"; done
echo "bob CORRECT password    -> HTTP $(login x bob "$PB")   (401 = locked)"
echo "unknown user            -> HTTP $(login x nosuchuser whatever)   (same generic message - no username enumeration)"
echo "-- administrator unlocks the account (ASD V-222433):"
docker compose exec -T flask flask --app app unlock-user bob
echo "bob CORRECT password    -> HTTP $(login x bob "$PB")   (302 = signed in)"

out "11. Previous sign-in shown to the user (ASD V-222437)"
login a alice "$PA" >/dev/null
curl -sk -b "$(jar a)" $B/ | grep -o 'Previous sign-in:[^<]*' | head -1 | tr -s ' \n' ' '; echo

out "12. Idle timeout after 15 minutes (ASD V-222389) - simulated by ageing the session"
db "import datetime as d; c.execute(\"update sessions set last_seen=? where user_id=(select id from users where username='alice')\", ((d.datetime.now(d.timezone.utc)-d.timedelta(minutes=16)).isoformat(),)); c.commit(); print('alice sessions aged by 16 minutes')"
curl -sk -b "$(jar a)" -o /dev/null -w "alice GET / -> HTTP %{http_code} -> %{redirect_url}\n" $B/

out "13. Logout destroys the session on the server (ASD V-222578, V-222388, V-222392)"
login a alice "$PA" >/dev/null
cp "$(jar a)" "$W/stolen.jar"
t=$(token a /)
curl -sk -b "$(jar a)" -c "$(jar a)" -D - -o "$W/out.html" --data-urlencode "csrf_token=$t" $B/logout | grep -i "clear-site-data"
grep -o "You have been signed out" "$W/out.html"
curl -sk -b "$W/stolen.jar" -o /dev/null -w "replay of copied pre-logout cookie -> HTTP %{http_code} -> %{redirect_url}\n" $B/

out "14. Concurrent sessions capped at 3 per user (ASD V-222387)"
for i in 1 2 3 4; do login s$i alice "$PA" >/dev/null; done
db "print('alice active sessions:', c.execute(\"select count(*) from sessions where user_id=(select id from users where username='alice')\").fetchone()[0])"

out "15. Brute-force throttling at nginx (HTTP 429 after burst)"
for i in $(seq 15); do curl -sk -o /dev/null -w "%{http_code} " -d "username=x&password=y" $B/login; done; echo

out "16. Audit trail of all of the above (identity + outcome on every record)"
alog | python3 -c "
import sys, json, collections
keep = {'account_create','login','account_lock','account_unlock','session_created','session_destroyed',
        'session_timeout','access_denied','csrf_check','file_encrypt','file_decrypt','file_delete','logout'}
counts = collections.Counter()
for line in sys.stdin:
    r = json.loads(line)
    if r['event'] in keep:
        counts[(r['event'], r['outcome'])] += 1
for (e, o), n in sorted(counts.items()):
    print(f'{e:18} {o:8} x{n}')"
echo "-- sample security events:"
alog | grep -E '"(account_lock|access_denied|session_timeout)"' | tail -3
echo "-- passwords or encryption key in log?"
for s in "$PA" "$PB" "${KEY:-no-key-captured}"; do
  printf '%s... -> ' "${s:0:6}"; alog | grep -cF -- "$s" || true
done
} 2>&1 | tee "$E/step6_results.txt"

rm -rf "$W"
echo; echo "Saved to $E/step6_results.txt"
