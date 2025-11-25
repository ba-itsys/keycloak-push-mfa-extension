#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/rotate-user-key.sh <credential-id>

Environment overrides:
  REALM_BASE          Realm base URL (default: value stored during enrollment, fallback http://localhost:8080/realms/demo)
  DEVICE_STATE_DIR    Directory storing device state from enroll.sh (default: scripts/device-state)
  NEW_DEVICE_KEY_ID   Key ID to embed in the new JWK (default: generated UUID)
  NEW_DEVICE_KEY_BITS RSA key size for the new key (default: 2048)
  NEW_DEVICE_KEY_TYPE Key type for the new key (RSA or EC, default: current type)
  NEW_DEVICE_EC_CURVE Curve for EC keys (P-256, P-384, P-521; default: current or P-256)
  NEW_DEVICE_ALG      Algorithm string persisted with the credential (default: matches key type)
  TOKEN_ENDPOINT      Override token endpoint (default: stored value)
  DEVICE_CLIENT_ID    Override OAuth client ID (default: stored value)
  DEVICE_CLIENT_SECRET Override OAuth client secret (default: stored value)
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -ne 1 ]]; then
  usage
  exit $([[ $# -eq 1 ]] && [[ ${1:-} != "-h" && ${1:-} != "--help" ]] && echo 1 || echo 0)
fi

CREDENTIAL_ID=$1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_SIGN_JWS="${COMMON_SIGN_JWS:-"$SCRIPT_DIR/sign_jws.py"}"
source "$SCRIPT_DIR/common.sh"
common::ensure_crypto
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEVICE_STATE_DIR=${DEVICE_STATE_DIR:-"$REPO_ROOT/scripts/device-state"}
STATE_FILE="$DEVICE_STATE_DIR/${CREDENTIAL_ID}.json"

if [[ ! -f "$STATE_FILE" ]]; then
  echo "error: device state file not found: $STATE_FILE" >&2
  exit 1
fi
NEW_DEVICE_KEY_BITS=${NEW_DEVICE_KEY_BITS:-2048}
NEW_DEVICE_KEY_ID=${NEW_DEVICE_KEY_ID:-$(python3 - <<'PY'
import uuid
print(f"user-key-{uuid.uuid4()}")
PY
)}

validate_signing_combo() {
  local key_type=$1
  local alg=$2
  local curve=$3
  case "$key_type" in
    RSA)
      case "$alg" in
        RS256|RS384|RS512) ;;
        *) echo "error: unsupported NEW_DEVICE_ALG '$alg' for RSA (use RS256/RS384/RS512)" >&2; exit 1 ;;
      esac
      ;;
    EC)
      case "$alg" in
        ES256) [[ "$curve" == "P-256" ]] || { echo "error: ES256 requires NEW_DEVICE_EC_CURVE=P-256" >&2; exit 1; } ;;
        ES384) [[ "$curve" == "P-384" ]] || { echo "error: ES384 requires NEW_DEVICE_EC_CURVE=P-384" >&2; exit 1; } ;;
        ES512) [[ "$curve" == "P-521" ]] || { echo "error: ES512 requires NEW_DEVICE_EC_CURVE=P-521" >&2; exit 1; } ;;
        *) echo "error: unsupported NEW_DEVICE_ALG '$alg' for EC (use ES256/ES384/ES512)" >&2; exit 1 ;;
      esac
      ;;
    *)
      echo "error: unsupported key type '$key_type'" >&2
      exit 1
      ;;
  esac
}


STATE=$(cat "$STATE_FILE")
USER_ID=$(echo "$STATE" | jq -r '.userId')
DEVICE_ID=$(echo "$STATE" | jq -r '.deviceId')
PRIVATE_KEY_B64=$(echo "$STATE" | jq -r '.privateKey')
KEY_ID=$(echo "$STATE" | jq -r '.keyId // "push-device-client-key"')
PUBLIC_JWK=$(echo "$STATE" | jq -c '.publicJwk // empty')
REALM_BASE_DEFAULT=$(echo "$STATE" | jq -r '.realmBase // empty')
REALM_BASE=${REALM_BASE:-$REALM_BASE_DEFAULT}
REALM_BASE=${REALM_BASE:-http://localhost:8080/realms/demo}
TOKEN_ENDPOINT_STATE=$(echo "$STATE" | jq -r '.tokenEndpoint // empty')
CLIENT_ID_STATE=$(echo "$STATE" | jq -r '.clientId // empty')
CLIENT_SECRET_STATE=$(echo "$STATE" | jq -r '.clientSecret // empty')
TOKEN_ENDPOINT=${TOKEN_ENDPOINT:-$TOKEN_ENDPOINT_STATE}
CLIENT_ID=${DEVICE_CLIENT_ID:-$CLIENT_ID_STATE}
CLIENT_SECRET=${DEVICE_CLIENT_SECRET:-$CLIENT_SECRET_STATE}
SIGNING_ALG=$(echo "$STATE" | jq -r '.signingAlg // (.publicJwk.alg // "RS256")')
SIGNING_ALG=$(common::to_upper "$SIGNING_ALG")
CURRENT_KEY_TYPE=$(echo "$STATE" | jq -r '.keyType // (.publicJwk.kty // "RSA")')
CURRENT_KEY_TYPE=$(common::to_upper "$CURRENT_KEY_TYPE")
CURRENT_EC_CURVE=$(echo "$STATE" | jq -r '.ecCurve // (.publicJwk.crv // "P-256")')
CURRENT_EC_CURVE=$(common::to_upper "$CURRENT_EC_CURVE")

NEW_DEVICE_KEY_TYPE=${NEW_DEVICE_KEY_TYPE:-$CURRENT_KEY_TYPE}
NEW_DEVICE_KEY_TYPE_UPPER=$(common::to_upper "$NEW_DEVICE_KEY_TYPE")
NEW_DEVICE_EC_CURVE=${NEW_DEVICE_EC_CURVE:-$CURRENT_EC_CURVE}
NEW_DEVICE_EC_CURVE=$(common::to_upper "$NEW_DEVICE_EC_CURVE")
if [[ "$NEW_DEVICE_KEY_TYPE_UPPER" != "EC" ]]; then
  NEW_DEVICE_EC_CURVE=""
elif [[ -z $NEW_DEVICE_EC_CURVE || $NEW_DEVICE_EC_CURVE == "NULL" ]]; then
  NEW_DEVICE_EC_CURVE="P-256"
fi
if [[ -z ${NEW_DEVICE_ALG:-} ]]; then
  if [[ "$NEW_DEVICE_KEY_TYPE_UPPER" == "EC" ]]; then
    case "$NEW_DEVICE_EC_CURVE" in
      P-256) NEW_DEVICE_ALG="ES256" ;;
      P-384) NEW_DEVICE_ALG="ES384" ;;
      P-521) NEW_DEVICE_ALG="ES512" ;;
      *) echo "error: unsupported NEW_DEVICE_EC_CURVE '$NEW_DEVICE_EC_CURVE' (use P-256/P-384/P-521)" >&2; exit 1 ;;
    esac
  else
    NEW_DEVICE_ALG="RS256"
  fi
fi
NEW_DEVICE_ALG=$(common::to_upper "$NEW_DEVICE_ALG")
validate_signing_combo "$NEW_DEVICE_KEY_TYPE_UPPER" "$NEW_DEVICE_ALG" "$NEW_DEVICE_EC_CURVE"

for value in "$USER_ID" "$DEVICE_ID" "$PRIVATE_KEY_B64" "$PUBLIC_JWK"; do
  if [[ -z $value || $value == "null" ]]; then
    echo "error: device state missing required fields" >&2
    exit 1
  fi
done
if [[ -z ${TOKEN_ENDPOINT:-} || -z ${CLIENT_ID:-} || -z ${CLIENT_SECRET:-} ]]; then
  echo "error: missing token endpoint or credentials" >&2
  exit 1
fi

WORKDIR=$(mktemp -d)
cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

KEY_FILE="$DEVICE_STATE_DIR/${CREDENTIAL_ID}.key"
printf '%s' "$PRIVATE_KEY_B64" | common::write_private_key "$KEY_FILE"

NEW_PRIV_PATH="$WORKDIR/new-device.key"
NEW_PUB_PATH="$WORKDIR/new-device.pub"
echo ">> Generating new user key pair ($NEW_DEVICE_KEY_TYPE_UPPER)"
if [[ "$NEW_DEVICE_KEY_TYPE_UPPER" == "EC" ]]; then
  case "$NEW_DEVICE_EC_CURVE" in
    P-256) OPENSSL_NEW_CURVE=prime256v1 ;;
    P-384) OPENSSL_NEW_CURVE=secp384r1 ;;
    P-521) OPENSSL_NEW_CURVE=secp521r1 ;;
    *) echo "error: unsupported NEW_DEVICE_EC_CURVE '$NEW_DEVICE_EC_CURVE' (use P-256/P-384/P-521)" >&2; exit 1 ;;
  esac
  openssl ecparam -name "$OPENSSL_NEW_CURVE" -genkey -noout -out "$NEW_PRIV_PATH" >/dev/null 2>&1
  openssl ec -in "$NEW_PRIV_PATH" -pubout -out "$NEW_PUB_PATH" >/dev/null 2>&1
else
  openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$NEW_DEVICE_KEY_BITS" -out "$NEW_PRIV_PATH" >/dev/null 2>&1
  openssl rsa -pubout -in "$NEW_PRIV_PATH" -out "$NEW_PUB_PATH" >/dev/null 2>&1
fi

NEW_JWK_PATH="$WORKDIR/new-device-jwk.json"
DEVICE_PUBLIC_KEY_PATH="$NEW_PUB_PATH" DEVICE_KEY_ID="$NEW_DEVICE_KEY_ID" DEVICE_KEY_TYPE="$NEW_DEVICE_KEY_TYPE_UPPER" DEVICE_EC_CURVE="$NEW_DEVICE_EC_CURVE" DEVICE_SIGNING_ALG="$NEW_DEVICE_ALG" python3 - <<'PY' > "$NEW_JWK_PATH"
import json, base64, os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

key_type = os.environ.get("DEVICE_KEY_TYPE", "RSA").upper()

with open(os.environ['DEVICE_PUBLIC_KEY_PATH'], 'rb') as fh:
    key = serialization.load_pem_public_key(fh.read(), backend=default_backend())

def b64_int(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')

def b64_bytes(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

if key_type == "RSA":
    numbers = key.public_numbers()
    jwk = {
        "kty": "RSA",
        "n": b64_int(numbers.n),
        "e": b64_int(numbers.e),
        "alg": os.environ.get("DEVICE_SIGNING_ALG", "RS256"),
        "use": "sig",
        "kid": os.environ.get("DEVICE_KEY_ID", "push-device-client-key")
    }
elif key_type == "EC":
    numbers = key.public_numbers()
    curve = os.environ.get("DEVICE_EC_CURVE", "P-256")
    jwk = {
        "kty": "EC",
        "crv": curve,
        "x": b64_int(numbers.x),
        "y": b64_int(numbers.y),
        "alg": os.environ.get("DEVICE_SIGNING_ALG", "ES256"),
        "use": "sig",
        "kid": os.environ.get("DEVICE_KEY_ID", "push-device-client-key")
    }
else:
    raise SystemExit(f"Unsupported DEVICE_KEY_TYPE: {key_type}")

print(json.dumps(jwk))
PY

TOKEN_RESPONSE=$(common::fetch_access_token "$TOKEN_ENDPOINT" "$CLIENT_ID" "$CLIENT_SECRET" "$KEY_FILE" "$PUBLIC_JWK" "$KEY_ID" "$USER_ID" "$DEVICE_ID" "$SIGNING_ALG")
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')
if [[ -z $ACCESS_TOKEN || $ACCESS_TOKEN == "null" ]]; then
  echo "error: failed to obtain access token" >&2
  echo "$TOKEN_RESPONSE" >&2
  exit 1
fi

ROTATE_URL="$REALM_BASE/push-mfa/device/rotate-key"
ROTATE_DPOP=$(common::create_dpop_proof "PUT" "$ROTATE_URL" "$KEY_FILE" "$PUBLIC_JWK" "$KEY_ID" "$USER_ID" "$DEVICE_ID" "$SIGNING_ALG")
echo ">> Rotating user key for $CREDENTIAL_ID"
RESPONSE=$(curl -s -X PUT \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $ROTATE_DPOP" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --argjson jwk "$(cat "$NEW_JWK_PATH")" --arg algorithm "$NEW_DEVICE_ALG" '{publicKeyJwk: $jwk, algorithm: $algorithm}')" \
  "$ROTATE_URL")
echo "$RESPONSE" | jq

NEW_PRIVATE_B64=$(base64 < "$NEW_PRIV_PATH" | tr -d '\n')
NEW_PUBLIC_B64=$(base64 < "$NEW_PUB_PATH" | tr -d '\n')
UPDATED_STATE=$(jq \
  --arg privateKey "$NEW_PRIVATE_B64" \
  --arg publicKey "$NEW_PUBLIC_B64" \
  --arg keyId "$NEW_DEVICE_KEY_ID" \
  --argjson publicJwk "$(cat "$NEW_JWK_PATH")" \
  --arg signingAlg "$NEW_DEVICE_ALG" \
  --arg keyType "$NEW_DEVICE_KEY_TYPE_UPPER" \
  --arg ecCurve "$NEW_DEVICE_EC_CURVE" \
  '.privateKey = $privateKey
   | .publicKey = $publicKey
   | .keyId = $keyId
   | .publicJwk = $publicJwk
   | .signingAlg = $signingAlg
   | .keyType = $keyType
   | .ecCurve = (if $keyType == "EC" then $ecCurve else null end)' \
  "$STATE_FILE")
printf '%s\n' "$UPDATED_STATE" > "$STATE_FILE"
echo ">> Updated device state in $STATE_FILE"
