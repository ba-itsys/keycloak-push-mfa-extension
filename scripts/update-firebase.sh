#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/update-firebase.sh <pseudonymous-user-id> <new-firebase-id>

Environment overrides:
  REALM_BASE        Realm base URL (default: value stored during enrollment, fallback http://localhost:8080/realms/push-mfa)
  DEVICE_STATE_DIR  Directory storing device state from enroll.sh (default: scripts/device-state)
  TOKEN_ENDPOINT    Override token endpoint (default: stored value)
  DEVICE_CLIENT_ID  Override OAuth client ID (default: stored value)
  DEVICE_CLIENT_SECRET Override OAuth client secret (default: stored value)
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -ne 2 ]]; then
  usage
  exit $([[ $# -eq 2 ]] && [[ ${1:-} != "-h" && ${1:-} != "--help" ]] && echo 1 || echo 0)
fi

PSEUDONYMOUS_ID=$1
NEW_FIREBASE_ID=$2

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIGN_JWS="$SCRIPT_DIR/sign_jws.py"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEVICE_STATE_DIR=${DEVICE_STATE_DIR:-"$REPO_ROOT/scripts/device-state"}
STATE_FILE="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.json"

if [[ ! -f "$STATE_FILE" ]]; then
  echo "error: device state file not found: $STATE_FILE" >&2
  exit 1
fi

b64urlencode() {
  python3 -c "import base64, sys; data = sys.stdin.buffer.read(); print(base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii'))"
}

require_crypto() {
  python3 - <<'PY' >/dev/null 2>&1
import importlib.util, sys
sys.exit(0 if importlib.util.find_spec("cryptography") else 1)
PY
}

if ! require_crypto; then
  echo "error: Python module 'cryptography' is required (install via 'python3 -m pip install --user cryptography')" >&2
  exit 1
fi

sign_compact_jws() {
  local alg=$1
  local key_file=$2
  local signing_input=$3
  python3 "$SIGN_JWS" "$alg" "$key_file" "$signing_input"
}

to_upper() {
  printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]'
}

create_dpop_proof() {
  local method=$1
  local url=$2
  local key_file=$3
  local jwk_json=$4
  local key_id=$5
  local user_id=$6
  local device_id=$7
  local alg=${8:-$SIGNING_ALG}
  local iat=$(date +%s)
  local jti=$(python3 - <<'PY'
import uuid
print(str(uuid.uuid4()))
PY
)
  local payload=$(jq -n \
    --arg htm "$method" \
    --arg htu "$url" \
    --arg sub "$user_id" \
    --arg deviceId "$device_id" \
    --arg iat "$iat" \
    --arg jti "$jti" \
    '{"htm": $htm, "htu": $htu, "sub": $sub, "deviceId": $deviceId, "iat": ($iat|tonumber), "jti": $jti}')
  local header_json=$(jq -cn --arg alg "$alg" --arg typ "dpop+jwt" --arg kid "$key_id" --argjson jwk "$jwk_json" '{alg:$alg,typ:$typ,kid:$kid,jwk:$jwk}')
  local header_b64=$(printf '%s' "$header_json" | b64urlencode)
  local payload_b64=$(printf '%s' "$payload" | b64urlencode)
  local signature_b64
  signature_b64=$(sign_compact_jws "$alg" "$key_file" "$header_b64.$payload_b64")
  echo "$header_b64.$payload_b64.$signature_b64"
}

STATE=$(cat "$STATE_FILE")
USER_ID=$(echo "$STATE" | jq -r '.userId')
DEVICE_ID=$(echo "$STATE" | jq -r '.deviceId')
PRIVATE_KEY_B64=$(echo "$STATE" | jq -r '.privateKey')
KEY_ID=$(echo "$STATE" | jq -r '.keyId // "push-device-client-key"')
PUBLIC_JWK=$(echo "$STATE" | jq -c '.publicJwk // empty')
REALM_BASE_DEFAULT=$(echo "$STATE" | jq -r '.realmBase // empty')
REALM_BASE=${REALM_BASE:-$REALM_BASE_DEFAULT}
REALM_BASE=${REALM_BASE:-http://localhost:8080/realms/push-mfa}
TOKEN_ENDPOINT_STATE=$(echo "$STATE" | jq -r '.tokenEndpoint // empty')
CLIENT_ID_STATE=$(echo "$STATE" | jq -r '.clientId // empty')
CLIENT_SECRET_STATE=$(echo "$STATE" | jq -r '.clientSecret // empty')
TOKEN_ENDPOINT=${TOKEN_ENDPOINT:-$TOKEN_ENDPOINT_STATE}
CLIENT_ID=${DEVICE_CLIENT_ID:-$CLIENT_ID_STATE}
CLIENT_SECRET=${DEVICE_CLIENT_SECRET:-$CLIENT_SECRET_STATE}
SIGNING_ALG=$(echo "$STATE" | jq -r '.signingAlg // (.publicJwk.alg // "RS256")')
SIGNING_ALG=$(to_upper "$SIGNING_ALG")

for value in "$USER_ID" "$DEVICE_ID" "$PRIVATE_KEY_B64" "$PUBLIC_JWK"; do
  if [[ -z $value || $value == "null" ]]; then
    echo "error: device state missing required fields" >&2
    exit 1
  fi
done
if [[ -z ${TOKEN_ENDPOINT:-} || -z ${CLIENT_ID:-} || -z ${CLIENT_SECRET:-} ]]; then
  echo "error: missing token endpoint or client credentials" >&2
  exit 1
fi

KEY_FILE="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.key"
python3 - "$PRIVATE_KEY_B64" "$KEY_FILE" <<'PY'
import base64, sys
b64 = sys.argv[1]
path = sys.argv[2]
with open(path, 'wb') as fh:
    fh.write(base64.b64decode(b64))
PY

TOKEN_DPOP=$(create_dpop_proof "POST" "$TOKEN_ENDPOINT" "$KEY_FILE" "$PUBLIC_JWK" "$KEY_ID" "$USER_ID" "$DEVICE_ID" "$SIGNING_ALG")
TOKEN_RESPONSE=$(curl -s -X POST \
  -H "DPoP: $TOKEN_DPOP" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  "$TOKEN_ENDPOINT")
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')
if [[ -z $ACCESS_TOKEN || $ACCESS_TOKEN == "null" ]]; then
  echo "error: failed to obtain access token" >&2
  echo "$TOKEN_RESPONSE" >&2
  exit 1
fi

UPDATE_URL="$REALM_BASE/push-mfa/device/firebase"
UPDATE_DPOP=$(create_dpop_proof "PUT" "$UPDATE_URL" "$KEY_FILE" "$PUBLIC_JWK" "$KEY_ID" "$USER_ID" "$DEVICE_ID" "$SIGNING_ALG")
echo ">> Updating Firebase ID for $PSEUDONYMOUS_ID"
curl -s -X PUT \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $UPDATE_DPOP" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg firebaseId "$NEW_FIREBASE_ID" '{"firebaseId": $firebaseId}')" \
  "$UPDATE_URL" | jq
