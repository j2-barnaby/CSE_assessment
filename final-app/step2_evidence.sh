#!/usr/bin/env bash
# Step 2 evidence: AES-256-GCM encryption, safe storage, no key leakage.
# Run from ~/CSE_assessment/final-app with the stack running.
# Uses plain HTTP on 443 because TLS is added in Step 3.
set -u
URL=${URL:-http://localhost:443}
E=../evidence/04-remediation/step2
mkdir -p "$E"
json() { python3 -c "import sys,json; print(json.load(sys.stdin)['$1'])"; }
out() { echo; echo "===== $1 ====="; }

{
out "1. Normal upload (key returned, no server path)"
echo "TESTFILE-12345 this is plaintext for Application_3" > /tmp/s2_plain.txt
R=$(curl -s -F "file=@/tmp/s2_plain.txt" "$URL/upload"); echo "$R"
ID=$(echo "$R" | json file_id); KEY=$(echo "$R" | json encryption_key)

out "2. Stored file is unreadable ciphertext (compare with XOR baseline)"
docker compose exec -T flask ls -l /data
docker compose exec -T flask sh -c "head -c 64 /data/$ID.enc" | xxd | head -4
docker compose exec -T flask sh -c "grep -c TESTFILE /data/$ID.enc || echo 'plaintext NOT found in ciphertext'"

out "3. Round trip: decrypt and compare SHA-256"
curl -s -o /tmp/s2_decrypted.txt -d "file_id=$ID" --data-urlencode "key=$KEY" "$URL/decrypt"
sha256sum /tmp/s2_plain.txt /tmp/s2_decrypted.txt

out "4. Wrong key is rejected"
BAD=$(python3 -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
curl -s -d "file_id=$ID" --data-urlencode "key=$BAD" "$URL/decrypt"; echo

out "5. Old attack: brute-force all 256 XOR keys against new ciphertext"
docker compose exec -T flask python - "$ID" <<'PY'
import sys
blob = open(f"/data/{sys.argv[1]}.enc", "rb").read()
hits = [k for k in range(256) if b"TESTFILE" in bytes(b ^ k for b in blob)]
print("XOR keys that reveal plaintext:", hits or "none - brute force fails")
PY

out "6. Path traversal filename is neutralised"
echo x > /tmp/s2_x.txt
curl -s -F "file=@/tmp/s2_x.txt;filename=../../../etc/passwd" "$URL/upload"; echo

out "7. Duplicate filenames do not overwrite each other"
curl -s -F "file=@/tmp/s2_plain.txt" "$URL/upload" | json file_id
curl -s -F "file=@/tmp/s2_plain.txt" "$URL/upload" | json file_id

out "8. Long filename is truncated safely"
LONG=$(python3 -c "print('A'*300+'.txt')")
curl -s -F "file=@/tmp/s2_x.txt;filename=$LONG" "$URL/upload" | json filename | wc -c

out "9. Empty file"
: > /tmp/s2_empty.txt
curl -s -F "file=@/tmp/s2_empty.txt" "$URL/upload"; echo

out "10. Oversized file (11 MB) is rejected"
head -c 11534336 /dev/zero > /tmp/s2_big.bin
curl -s -o /dev/null -w "HTTP %{http_code}\n" -F "file=@/tmp/s2_big.bin" "$URL/upload"

out "11. Missing file field"
curl -s -F "wrong=@/tmp/s2_x.txt" "$URL/upload"; echo

out "12. Key is NOT in the log"
grep -c -- "$KEY" logs/flask_app.log || echo "key not present in log"
tail -5 logs/flask_app.log

out "13. Persistence across restart"
docker compose down >/dev/null 2>&1 && docker compose up -d >/dev/null 2>&1 && sleep 4
curl -s -o /tmp/s2_after_restart.txt -d "file_id=$ID" --data-urlencode "key=$KEY" "$URL/decrypt"
sha256sum /tmp/s2_plain.txt /tmp/s2_after_restart.txt
} 2>&1 | tee "$E/step2_results.txt"

echo; echo "Saved to $E/step2_results.txt"
