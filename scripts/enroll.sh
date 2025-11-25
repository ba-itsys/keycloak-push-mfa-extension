#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/enroll.sh <enrollment-token>

Environment overrides:
  REALM_BASE               Realm base URL (default: http://localhost:8080/realms/demo)
  ENROLL_COMPLETE_URL      Enrollment completion endpoint (default: <REALM_BASE>/push-mfa/enroll/complete)
  TOKEN_ENDPOINT           OAuth2 token endpoint (default: <REALM_BASE>/protocol/openid-connect/token)
  DEVICE_CLIENT_ID         Client ID to request device tokens (default: push-device-client)
  DEVICE_CLIENT_SECRET     Client secret for the device client (default: device-client-secret)
  DEVICE_TYPE              Device type stored with the credential (default: ios)
  PUSH_PROVIDER_ID         Push provider identifier/token (default: demo-push-provider-token)
  PUSH_PROVIDER_TYPE       Push provider type / Keycloak SPI id (default: log)
  CREDENTIAL_ID            Credential identifier stored with the user (default: generated UUID)
  DEVICE_ID                Unique device id stored with the credential (default: generated UUID)
  DEVICE_LABEL             Display label stored with the credential (default: "Demo Phone")
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -ne 1 ]]; then
  usage
  exit $([[ $# -eq 1 ]] && [[ ${1:-} != "-h" && ${1:-} != "--help" ]] && echo 1 || echo 0)
fi

ENROLL_TOKEN=$1
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_SIGN_JWS="${COMMON_SIGN_JWS:-"$SCRIPT_DIR/sign_jws.py"}"
source "$SCRIPT_DIR/common.sh"
common::ensure_crypto

validate_signing_alg() {
  local alg="$1"
  case "$DEVICE_KEY_TYPE_UPPER" in
    RSA)
      case "$alg" in
        RS256|RS384|RS512) ;;
        *) echo "error: unsupported DEVICE_SIGNING_ALG '$alg' for RSA (use RS256/RS384/RS512)" >&2; exit 1 ;;
      esac
      ;;
    EC)
      case "$alg" in
        ES256) [[ "$DEVICE_EC_CURVE" == "P-256" ]] || { echo "error: ES256 requires DEVICE_EC_CURVE=P-256" >&2; exit 1; } ;;
        ES384) [[ "$DEVICE_EC_CURVE" == "P-384" ]] || { echo "error: ES384 requires DEVICE_EC_CURVE=P-384" >&2; exit 1; } ;;
        ES512) [[ "$DEVICE_EC_CURVE" == "P-521" ]] || { echo "error: ES512 requires DEVICE_EC_CURVE=P-521" >&2; exit 1; } ;;
        *) echo "error: unsupported DEVICE_SIGNING_ALG '$alg' for EC (use ES256/ES384/ES512)" >&2; exit 1 ;;
      esac
      ;;
    *)
      echo "error: unsupported DEVICE_KEY_TYPE '$DEVICE_KEY_TYPE_UPPER'" >&2
      exit 1
      ;;
  esac
}


REALM_BASE=${REALM_BASE:-http://localhost:8080/realms/demo}
ENROLL_COMPLETE_URL=${ENROLL_COMPLETE_URL:-$REALM_BASE/push-mfa/enroll/complete}
TOKEN_ENDPOINT=${TOKEN_ENDPOINT:-$REALM_BASE/protocol/openid-connect/token}
DEVICE_CLIENT_ID=${DEVICE_CLIENT_ID:-push-device-client}
DEVICE_CLIENT_SECRET=${DEVICE_CLIENT_SECRET:-device-client-secret}
DEVICE_TYPE=${DEVICE_TYPE:-ios}
PUSH_PROVIDER_ID=${PUSH_PROVIDER_ID:-demo-push-provider-token}
PUSH_PROVIDER_TYPE=${PUSH_PROVIDER_TYPE:-log}
CREDENTIAL_ID=${CREDENTIAL_ID:-$(python3 - <<'PY'
import uuid
print(f"credential-{uuid.uuid4()}")
PY
)}
DEVICE_ID=${DEVICE_ID:-$(python3 - <<'PY'
import uuid
print(f"device-{uuid.uuid4()}")
PY
)}
DEVICE_KEY_ID=${DEVICE_KEY_ID:-$(python3 - <<'PY'
import uuid
print(f"user-key-{uuid.uuid4()}")
PY
)}
DEVICE_LABEL=${DEVICE_LABEL:-Demo Phone}
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEVICE_STATE_DIR=${DEVICE_STATE_DIR:-"$REPO_ROOT/scripts/device-state"}
mkdir -p "$DEVICE_STATE_DIR"
DEVICE_PRIVATE_KEY_PATH="$DEVICE_STATE_DIR/${CREDENTIAL_ID}.key"
DEVICE_PUBLIC_KEY_PATH="$DEVICE_STATE_DIR/${CREDENTIAL_ID}.pub"
DEVICE_KEY_TYPE=${DEVICE_KEY_TYPE:-RSA}
DEVICE_KEY_TYPE_UPPER=$(common::to_upper "$DEVICE_KEY_TYPE")
DEVICE_EC_CURVE=${DEVICE_EC_CURVE:-P-256}
DEVICE_EC_CURVE=$(common::to_upper "$DEVICE_EC_CURVE")

case "$DEVICE_KEY_TYPE_UPPER" in
  RSA)
    DEVICE_SIGNING_ALG=${DEVICE_SIGNING_ALG:-RS256}
    ;;
  EC)
    case "$DEVICE_EC_CURVE" in
      P-256) OPENSSL_EC_CURVE=prime256v1; DEFAULT_EC_ALG=ES256 ;;
      P-384) OPENSSL_EC_CURVE=secp384r1;  DEFAULT_EC_ALG=ES384 ;;
      P-521) OPENSSL_EC_CURVE=secp521r1;  DEFAULT_EC_ALG=ES512 ;;
      *) echo "error: unsupported DEVICE_EC_CURVE '$DEVICE_EC_CURVE' (use P-256, P-384, or P-521)" >&2; exit 1 ;;
    esac
    DEVICE_SIGNING_ALG=${DEVICE_SIGNING_ALG:-$DEFAULT_EC_ALG}
    ;;
  *)
    echo "error: unsupported DEVICE_KEY_TYPE '$DEVICE_KEY_TYPE' (use RSA or EC)" >&2
    exit 1
    ;;
esac
DEVICE_SIGNING_ALG=$(common::to_upper "$DEVICE_SIGNING_ALG")
validate_signing_alg "$DEVICE_SIGNING_ALG"

if [[ "$DEVICE_KEY_TYPE_UPPER" != "EC" ]]; then
  DEVICE_EC_CURVE=""
fi

WORKDIR=$(mktemp -d)
cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

pushd "$WORKDIR" >/dev/null

echo ">> Decoding enrollment challenge"
ENROLL_PAYLOAD=$(echo -n "$ENROLL_TOKEN" | cut -d'.' -f2 | common::b64urldecode)
ENROLLMENT_ID=$(echo "$ENROLL_PAYLOAD" | jq -r '.enrollmentId')
ENROLL_NONCE=$(echo "$ENROLL_PAYLOAD" | jq -r '.nonce')
USER_ID=$(echo "$ENROLL_PAYLOAD" | jq -r '.sub')

if [[ -z $ENROLLMENT_ID || -z $ENROLL_NONCE || -z $USER_ID ]]; then
  echo "error: unable to extract enrollmentId/nonce/sub from challenge" >&2
  exit 1
fi

echo "   enrollmentId: $ENROLLMENT_ID"
echo "   userId      : $USER_ID"

echo ">> Generating user key pair ($DEVICE_KEY_TYPE_UPPER)"
if [[ "$DEVICE_KEY_TYPE_UPPER" == "EC" ]]; then
  openssl ecparam -name "$OPENSSL_EC_CURVE" -genkey -noout -out "$DEVICE_PRIVATE_KEY_PATH" >/dev/null 2>&1
  openssl ec -in "$DEVICE_PRIVATE_KEY_PATH" -pubout -out "$DEVICE_PUBLIC_KEY_PATH" >/dev/null 2>&1
else
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$DEVICE_PRIVATE_KEY_PATH" >/dev/null 2>&1
  openssl rsa -pubout -in "$DEVICE_PRIVATE_KEY_PATH" -out "$DEVICE_PUBLIC_KEY_PATH" >/dev/null 2>&1
fi

echo ">> Building JWK from public key"
DEVICE_PUBLIC_KEY_PATH="$DEVICE_PUBLIC_KEY_PATH" DEVICE_KEY_ID="$DEVICE_KEY_ID" DEVICE_KEY_TYPE="$DEVICE_KEY_TYPE_UPPER" DEVICE_EC_CURVE="$DEVICE_EC_CURVE" DEVICE_SIGNING_ALG="$DEVICE_SIGNING_ALG" python3 - <<'PY' > device-jwk.json
import json, base64, os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

key_type = os.environ.get("DEVICE_KEY_TYPE", "RSA").upper()

with open(os.environ['DEVICE_PUBLIC_KEY_PATH'], 'rb') as f:
    key = serialization.load_pem_public_key(f.read(), backend=default_backend())

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

EXPIRY=$(($(date +%s) + 300))
echo ">> Preparing enrollment response JWT"
ENROLL_PAYLOAD_JSON=$(jq -n \
  --arg enrollmentId "$ENROLLMENT_ID" \
  --arg nonce "$ENROLL_NONCE" \
  --arg sub "$USER_ID" \
  --arg deviceType "$DEVICE_TYPE" \
  --arg pushProviderId "$PUSH_PROVIDER_ID" \
  --arg pushProviderType "$PUSH_PROVIDER_TYPE" \
  --arg credentialId "$CREDENTIAL_ID" \
  --arg deviceId "$DEVICE_ID" \
  --arg deviceLabel "$DEVICE_LABEL" \
  --arg exp "$EXPIRY" \
  --argjson cnf "$(jq -c '{"jwk": .}' device-jwk.json)" \
  '{"enrollmentId": $enrollmentId, "nonce": $nonce, "sub": $sub, "deviceType": $deviceType, "pushProviderId": $pushProviderId, "pushProviderType": $pushProviderType, "credentialId": $credentialId, "deviceId": $deviceId, "deviceLabel": $deviceLabel, "exp": ($exp|tonumber), "cnf": $cnf}')

ENROLL_HEADER_JSON=$(jq -nc \
  --arg alg "$DEVICE_SIGNING_ALG" \
  --arg kid "$DEVICE_KEY_ID" \
  '{alg:$alg,typ:"JWT",kid:$kid}')
ENROLL_HEADER_B64=$(printf '%s' "$ENROLL_HEADER_JSON" | common::b64urlencode)
ENROLL_PAYLOAD_B64=$(printf '%s' "$ENROLL_PAYLOAD_JSON" | common::b64urlencode)
ENROLL_SIGNATURE_B64=$(common::sign_compact_jws "$DEVICE_SIGNING_ALG" "$DEVICE_PRIVATE_KEY_PATH" "$ENROLL_HEADER_B64.$ENROLL_PAYLOAD_B64")
DEVICE_ENROLL_TOKEN="$ENROLL_HEADER_B64.$ENROLL_PAYLOAD_B64.$ENROLL_SIGNATURE_B64"

echo ">> Submitting enrollment reply"
echo $ENROLL_PAYLOAD_JSON
ENROLL_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg token "$DEVICE_ENROLL_TOKEN" '{"token": $token}')" \
  "$ENROLL_COMPLETE_URL")

echo "$ENROLL_RESPONSE" | jq

PRIVATE_KEY_B64=$(base64 < "$DEVICE_PRIVATE_KEY_PATH" | tr -d '\n')
PUBLIC_KEY_B64=$(base64 < "$DEVICE_PUBLIC_KEY_PATH" | tr -d '\n')
STATE_FILE="$DEVICE_STATE_DIR/${CREDENTIAL_ID}.json"

PUBLIC_JWK=$(cat device-jwk.json)

jq -n \
  --arg userId "$USER_ID" \
  --arg credentialId "$CREDENTIAL_ID" \
  --arg deviceId "$DEVICE_ID" \
  --arg realmBase "$REALM_BASE" \
  --arg tokenEndpoint "$TOKEN_ENDPOINT" \
  --arg clientId "$DEVICE_CLIENT_ID" \
  --arg clientSecret "$DEVICE_CLIENT_SECRET" \
  --arg privateKey "$PRIVATE_KEY_B64" \
  --arg publicKey "$PUBLIC_KEY_B64" \
  --arg deviceType "$DEVICE_TYPE" \
  --arg pushProviderId "$PUSH_PROVIDER_ID" \
  --arg pushProviderType "$PUSH_PROVIDER_TYPE" \
  --arg keyId "$DEVICE_KEY_ID" \
  --arg deviceLabel "$DEVICE_LABEL" \
  --argjson publicJwk "$PUBLIC_JWK" \
  --arg signingAlg "$DEVICE_SIGNING_ALG" \
  --arg keyType "$DEVICE_KEY_TYPE_UPPER" \
  --arg ecCurve "$DEVICE_EC_CURVE" \
  '{userId:$userId,
    credentialId:$credentialId,
    deviceId:$deviceId,
    realmBase:$realmBase,
    tokenEndpoint:$tokenEndpoint,
    clientId:$clientId,
    clientSecret:$clientSecret,
    privateKey:$privateKey,
    publicKey:$publicKey,
    deviceType:$deviceType,
    pushProviderId:$pushProviderId,
    pushProviderType:$pushProviderType,
    keyId:$keyId,
    deviceLabel:$deviceLabel,
    publicJwk:$publicJwk,
    signingAlg:$signingAlg,
    keyType:$keyType,
    ecCurve: (if $keyType == "EC" then $ecCurve else null end)}' > "$STATE_FILE"

echo ">> Device state stored in $STATE_FILE"
popd >/dev/null
