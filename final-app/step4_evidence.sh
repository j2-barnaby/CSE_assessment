#!/usr/bin/env bash
# Step 4 evidence: non-root, read-only, capability-free containers + patched images.
# Run from ~/CSE_assessment/final-app with the stack running.
set -u
E=../evidence/04-remediation/step4
mkdir -p "$E"
json() { python3 -c "import sys,json; print(json.load(sys.stdin)['$1'])"; }
out() { echo; echo "===== $1 ====="; }
grype() { docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest "$@"; }
count() { grep -oE "\b(Critical|High|Medium|Low|Negligible|Unknown)\b" "$1" | sort | uniq -c; }

{
out "1. Containers, health and port mapping"
docker compose ps

out "2. Which user each container runs as (baseline: root)"
echo -n "flask: "; docker compose exec -T flask id
echo -n "nginx: "; docker compose exec -T nginx id
echo "nginx processes:"; docker compose exec -T nginx ps -o user,pid,args | head -5

out "3. Hardening settings applied by Docker"
for c in final-app-flask-1 final-app-nginx-1; do
  docker inspect -f "$c: ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}} CapDrop={{.HostConfig.CapDrop}} SecurityOpt={{.HostConfig.SecurityOpt}} Privileged={{.HostConfig.Privileged}} PidsLimit={{.HostConfig.PidsLimit}} Memory={{.HostConfig.Memory}} Restart={{.HostConfig.RestartPolicy.Name}} User={{.Config.User}}" "$c"
done

out "4. Effective Linux capabilities inside the containers (0 = none)"
docker compose exec -T flask sh -c 'grep CapEff /proc/1/status'
docker compose exec -T nginx sh -c 'grep CapEff /proc/1/status'

out "5. Root filesystem is read-only (attempted writes must fail)"
docker compose exec -T flask sh -c 'touch /app/app.py 2>&1 || true; echo hacked > /app/evil.py 2>&1 || true; touch /etc/passwd 2>&1 || true'
docker compose exec -T nginx sh -c 'echo hacked > /etc/nginx/nginx.conf 2>&1 || true'

out "6. Cannot become root (no sudo/su, no setuid binaries)"
docker compose exec -T flask sh -c 'su -c id </dev/null 2>&1 | head -1; ls -l /bin/su; echo "setuid/setgid files: $(find / -xdev -perm /6000 -type f 2>/dev/null | wc -l)"'

out "7. pip removed from the runtime image"
docker compose exec -T flask sh -c 'python -m pip --version 2>&1 | head -1'

out "8. File and socket permissions"
docker compose exec -T flask sh -c 'ls -ln /run/app/; ls -ln /data | head -5'
docker compose exec -T flask sh -c 'ls -ln /app/logs/'
echo -n "cert key: "; ls -ln certs/nginx.key

out "9. Functional round trip still works over HTTPS"
echo "TESTFILE-12345 step4 hardened" > /tmp/s4_plain.txt
R=$(curl -sk -F "file=@/tmp/s4_plain.txt" https://localhost/upload); echo "$R"
ID=$(echo "$R" | json file_id); KEY=$(echo "$R" | json encryption_key)
curl -sk -o /tmp/s4_decrypted.txt -d "file_id=$ID" --data-urlencode "key=$KEY" https://localhost/decrypt
sha256sum /tmp/s4_plain.txt /tmp/s4_decrypted.txt
curl -s -o /dev/null -w "HTTP->HTTPS redirect still works: %{http_code} -> %{redirect_url}\n" http://localhost/

out "10. Self-healing: kill gunicorn, Docker restarts it"
docker compose exec -T flask sh -c 'kill 1' ; sleep 12
docker compose ps flask

out "11. Grype CVE scan after patching (same day, same DB)"
grype final-app-flask:latest -o table > "$E/grype_flask_step4.txt" 2>/dev/null
grype final-app-nginx:latest -o table > "$E/grype_nginx_step4.txt" 2>/dev/null
grype nginx:alpine -o table > "$E/grype_nginx_original_sameday.txt" 2>/dev/null
echo "--- flask (step 4)";        count "$E/grype_flask_step4.txt"
echo "--- flask fixable Highs:";  grep -E "\bHigh\b" "$E/grype_flask_step4.txt" | grep -vc "won't fix"
echo "--- nginx original (nginx:alpine)"; count "$E/grype_nginx_original_sameday.txt"
echo "--- nginx (step 4)";        count "$E/grype_nginx_step4.txt"
} 2>&1 | tee "$E/step4_results.txt"

echo; echo "Saved to $E/step4_results.txt"
