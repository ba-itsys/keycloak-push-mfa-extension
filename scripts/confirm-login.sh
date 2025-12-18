#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/confirm-login.sh <confirm-token>

Environment overrides:
  REALM_BASE               Realm base URL (default: http://localhost:8080/realms/demo). Falls back to stored value.
  DEVICE_STATE_DIR         Directory storing device state from enroll.sh (default: scripts/device-state)
  LOGIN_ACTION             Action encoded in the device token (approve or deny, default: approve)
  LOGIN_USER_VERIFICATION  Selected number / entered PIN for userVerification modes (optional; prompted if required)
  TOKEN_ENDPOINT           Override token endpoint (default: stored value)
  DEVICE_CLIENT_ID         Override OAuth client ID (default: stored value)
  DEVICE_CLIENT_SECRET     Override OAuth client secret (default: stored value)
EOF
}

require_or_prompt_user_verification() {
  local label=$1
  local prompt=$2
  if [[ -n ${LOGIN_USER_VERIFICATION:-} ]]; then
    return
  fi
  if [[ -t 0 ]]; then
    read -r -p "$prompt" LOGIN_USER_VERIFICATION
    return
  fi
  echo "error: $label user verification required (set LOGIN_USER_VERIFICATION)" >&2
  exit 1
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -ne 1 ]]; then
  usage
  exit $([[ $# -eq 1 ]] && [[ ${1:-} != "-h" && ${1:-} != "--help" ]] && echo 1 || echo 0)
fi

CONFIRM_TOKEN=$1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_SIGN_JWS="${COMMON_SIGN_JWS:-"$SCRIPT_DIR/sign_jws.py"}"
source "$SCRIPT_DIR/common.sh"
common::ensure_crypto

REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEVICE_STATE_DIR=${DEVICE_STATE_DIR:-"$REPO_ROOT/scripts/device-state"}

if [[ ! -d "$DEVICE_STATE_DIR" ]]; then
  echo "error: device state directory '$DEVICE_STATE_DIR' does not exist" >&2
  exit 1
fi

echo ">> Decoding confirm token"
CONFIRM_PAYLOAD=$(echo -n "$CONFIRM_TOKEN" | cut -d'.' -f2 | common::b64urldecode)
if [[ -z $CONFIRM_PAYLOAD ]]; then
  echo "error: invalid confirm token" >&2
  exit 1
fi

CREDENTIAL_ID=$(echo "$CONFIRM_PAYLOAD" | jq -r '.credId // empty')
CHALLENGE_ID=$(echo "$CONFIRM_PAYLOAD" | jq -r '.cid // empty')
if [[ -z $CREDENTIAL_ID || $CREDENTIAL_ID == "null" ]]; then
  echo "error: confirm token missing credential id" >&2
  exit 1
fi
if [[ -z $CHALLENGE_ID || $CHALLENGE_ID == "null" ]]; then
  echo "error: confirm token missing challenge id" >&2
  exit 1
fi

STATE_FILE="$DEVICE_STATE_DIR/${CREDENTIAL_ID}.json"
if [[ ! -f "$STATE_FILE" ]]; then
  echo "error: no device state found for credential id '$CREDENTIAL_ID'" >&2
  exit 1
fi

STATE=$(cat "$STATE_FILE")
USER_ID=$(echo "$STATE" | jq -r '.userId')
DEVICE_ID=$(echo "$STATE" | jq -r '.deviceId')
PRIVATE_KEY_B64=$(echo "$STATE" | jq -r '.privateKey')
KID=$(echo "$STATE" | jq -r '.keyId // "push-device-client-key"')
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

if [[ -z $USER_ID || -z $DEVICE_ID || -z $PRIVATE_KEY_B64 || -z $PUBLIC_JWK || -z ${TOKEN_ENDPOINT:-} || -z ${CLIENT_ID:-} || -z ${CLIENT_SECRET:-} ]]; then
  echo "error: device state missing required fields" >&2
  exit 1
fi

KEY_FILE="$DEVICE_STATE_DIR/${CREDENTIAL_ID}.key"
printf '%s' "$PRIVATE_KEY_B64" | common::write_private_key "$KEY_FILE"

TOKEN_RESPONSE=$(common::fetch_access_token "$TOKEN_ENDPOINT" "$CLIENT_ID" "$CLIENT_SECRET" "$KEY_FILE" "$PUBLIC_JWK" "$KID" "$USER_ID" "$DEVICE_ID" "$SIGNING_ALG")
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')
if [[ -z $ACCESS_TOKEN || $ACCESS_TOKEN == "null" ]]; then
  echo "error: failed to obtain access token" >&2
  echo "$TOKEN_RESPONSE" >&2
  exit 1
fi

PENDING_URL="$REALM_BASE/push-mfa/login/pending"
PENDING_HTU="$PENDING_URL?userId=$USER_ID"
echo ">> Demo: listing pending challenges (response is informational)"
PENDING_DPOP=$(common::create_dpop_proof "GET" "$PENDING_HTU" "$KEY_FILE" "$PUBLIC_JWK" "$KID" "$USER_ID" "$DEVICE_ID" "$SIGNING_ALG")
PENDING_RESPONSE=$(curl -s -G \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $PENDING_DPOP" \
  --data-urlencode "userId=$USER_ID" \
  "$PENDING_URL")
echo "$PENDING_RESPONSE" | jq

EXPIRY=$(($(date +%s) + 120))
LOGIN_ACTION=${LOGIN_ACTION:-approve}
LOGIN_ACTION=$(printf '%s' "${LOGIN_ACTION:-}" | tr '[:upper:]' '[:lower:]')
LOGIN_USER_VERIFICATION=${LOGIN_USER_VERIFICATION:-}

PENDING_CHALLENGE=$(echo "$PENDING_RESPONSE" | jq -c --arg cid "$CHALLENGE_ID" '
  .challenges // []
  | map(select(.cid == $cid))
  | first // empty
')
PENDING_UV_TYPE=""
PENDING_UV_NUMBERS_CSV=""
PENDING_UV_PIN_LENGTH=""
if [[ -n ${PENDING_CHALLENGE:-} ]]; then
  PENDING_UV_TYPE=$(echo "$PENDING_CHALLENGE" | jq -r '.userVerification.type // empty')
  PENDING_UV_NUMBERS_CSV=$(echo "$PENDING_CHALLENGE" | jq -r '.userVerification.numbers // [] | join(",")')
  PENDING_UV_PIN_LENGTH=$(echo "$PENDING_CHALLENGE" | jq -r '.userVerification.pinLength // empty')
fi

if [[ $LOGIN_ACTION == "approve" ]]; then
  if [[ $PENDING_UV_TYPE == "number-match" ]]; then
    if [[ -n $PENDING_UV_NUMBERS_CSV ]]; then
      echo ">> userVerification=number-match options: $PENDING_UV_NUMBERS_CSV"
    fi
    require_or_prompt_user_verification "number-match" "Enter the number shown in the browser: "
    if [[ ! $LOGIN_USER_VERIFICATION =~ ^(0|[1-9][0-9]?)$ ]]; then
      echo "error: LOGIN_USER_VERIFICATION must be a number 0-99 without leading zeros" >&2
      exit 1
    fi
    if [[ -n $PENDING_UV_NUMBERS_CSV ]]; then
      found=0
      IFS=',' read -r -a pending_numbers <<< "$PENDING_UV_NUMBERS_CSV"
      for option in "${pending_numbers[@]}"; do
        if [[ $option == "$LOGIN_USER_VERIFICATION" ]]; then
          found=1
          break
        fi
      done
      if [[ $found -ne 1 ]]; then
        echo "error: LOGIN_USER_VERIFICATION must be one of: $PENDING_UV_NUMBERS_CSV" >&2
        exit 1
      fi
    fi
  elif [[ $PENDING_UV_TYPE == "pin" ]]; then
    if [[ -n $PENDING_UV_PIN_LENGTH ]]; then
      echo ">> userVerification=pin length: $PENDING_UV_PIN_LENGTH"
    else
      PENDING_UV_PIN_LENGTH=4
      echo ">> userVerification=pin length: $PENDING_UV_PIN_LENGTH (default)"
    fi
    require_or_prompt_user_verification "pin" "Enter the PIN shown in the browser: "
    if [[ ! $LOGIN_USER_VERIFICATION =~ ^[0-9]+$ ]]; then
      echo "error: LOGIN_USER_VERIFICATION must be numeric" >&2
      exit 1
    fi
    if [[ ${#LOGIN_USER_VERIFICATION} -ne $PENDING_UV_PIN_LENGTH ]]; then
      echo "error: LOGIN_USER_VERIFICATION must be $PENDING_UV_PIN_LENGTH digits" >&2
      exit 1
    fi
  fi
fi

LOGIN_PAYLOAD=$(jq -n \
  --arg cid "$CHALLENGE_ID" \
  --arg credId "$CREDENTIAL_ID" \
  --arg deviceId "$DEVICE_ID" \
  --arg exp "$EXPIRY" \
  --arg action "$LOGIN_ACTION" \
  --arg uv "$LOGIN_USER_VERIFICATION" \
  '{"cid": $cid, "credId": $credId, "deviceId": $deviceId, "exp": ($exp|tonumber), "action": ($action|ascii_downcase)}
   + (if ($uv|length) > 0 then {"userVerification": $uv} else {} end)')
LOGIN_HEADER_JSON=$(jq -nc --arg alg "$SIGNING_ALG" --arg kid "$KID" '{alg:$alg,typ:"JWT",kid:$kid}')
LOGIN_HEADER_B64=$(printf '%s' "$LOGIN_HEADER_JSON" | common::b64urlencode)
LOGIN_PAYLOAD_B64=$(printf '%s' "$LOGIN_PAYLOAD" | common::b64urlencode)
LOGIN_SIGNATURE_B64=$(common::sign_compact_jws "$SIGNING_ALG" "$KEY_FILE" "$LOGIN_HEADER_B64.$LOGIN_PAYLOAD_B64")
DEVICE_LOGIN_TOKEN="$LOGIN_HEADER_B64.$LOGIN_PAYLOAD_B64.$LOGIN_SIGNATURE_B64"

RESPOND_URL="$REALM_BASE/push-mfa/login/challenges/$CHALLENGE_ID/respond"
LOGIN_DPOP=$(common::create_dpop_proof "POST" "$RESPOND_URL" "$KEY_FILE" "$PUBLIC_JWK" "$KID" "$USER_ID" "$DEVICE_ID" "$SIGNING_ALG")
echo ">> Responding to challenge"
curl -s -X POST \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $LOGIN_DPOP" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg token "$DEVICE_LOGIN_TOKEN" '{"token": $token}')" \
  "$RESPOND_URL" | jq
