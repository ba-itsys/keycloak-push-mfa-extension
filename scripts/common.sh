#!/usr/bin/env bash
# Shared helper functions for demo scripts.

if [[ -n ${COMMON_SH_INCLUDED:-} ]]; then
  return
fi
COMMON_SH_INCLUDED=1

common::to_upper() {
  printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]'
}

common::ensure_crypto() {
  if [[ -n ${COMMON_CRYPTO_READY:-} ]]; then
    return
  fi
  if python3 - <<'PY' >/dev/null 2>&1; then
import importlib.util, sys
sys.exit(0 if importlib.util.find_spec("cryptography") else 1)
PY
    COMMON_CRYPTO_READY=1
  else
    echo "error: Python module 'cryptography' is required (install via 'python3 -m pip install --user cryptography')" >&2
    exit 1
  fi
}

common::urlencode() {
  python3 -c "import urllib.parse, sys; sys.stdout.write(urllib.parse.quote(sys.stdin.read(), safe=''))"
}

common::b64urlencode() {
  python3 -c "import base64, sys; data = sys.stdin.buffer.read(); sys.stdout.write(base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii'))"
}

common::b64urldecode() {
  python3 -c "import base64, sys; data = sys.stdin.read().strip().replace('-', '+').replace('_', '/'); data += '=' * (-len(data) % 4); sys.stdout.buffer.write(base64.urlsafe_b64decode(data))"
}

common::write_private_key() {
  local path=$1
  python3 -c "import base64, pathlib, sys; payload=sys.stdin.read().strip(); pathlib.Path(sys.argv[1]).write_bytes(base64.b64decode(payload))" "$path"
}

common::extract_query_param() {
  local input=$1
  local param=$2
  python3 - "$input" "$param" <<'PY'
import sys
from urllib.parse import parse_qs, urlparse

input_value = sys.argv[1]
param = sys.argv[2]
parsed = urlparse(input_value)
values = parse_qs(parsed.query).get(param, [])
if values:
    sys.stdout.write(values[0])
PY
}

common::resolve_token_input() {
  local input=$1
  local token
  token=$(common::extract_query_param "$input" "token")
  if [[ -n ${token:-} ]]; then
    printf '%s\n' "$token"
    return
  fi

  local request_uri
  request_uri=$(common::extract_query_param "$input" "request_uri")
  if [[ -n ${request_uri:-} ]]; then
    common::resolve_token_input "$request_uri"
    return
  fi

  if [[ $input =~ ^https?:// ]]; then
    curl -fsS "$input"
    return
  fi

  printf '%s\n' "$input"
}

common::sign_compact_jws() {
  local alg=$1
  local key_file=$2
  local signing_input=$3
  local signer=${COMMON_SIGN_JWS:-}
  if [[ -z ${signer:-} ]]; then
    echo "error: COMMON_SIGN_JWS is not configured" >&2
    exit 1
  fi
  python3 "$signer" "$alg" "$key_file" "$signing_input"
}

common::new_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr '[:upper:]' '[:lower:]'
  else
    python3 - <<'PY'
import uuid
print(str(uuid.uuid4()))
PY
  fi
}

common::create_dpop_proof() {
  local method=$1
  local url=$2
  local key_file=$3
  local jwk_json=$4
  local key_id=$5
  local user_id=$6
  local device_id=$7
  local alg=${8:-RS256}
  local access_token=${9:-}
  local iat
  iat=$(date +%s)
  local jti
  jti=$(common::new_uuid)
  local payload
  payload=$(jq -n \
    --arg htm "$method" \
    --arg htu "$url" \
    --arg sub "$user_id" \
    --arg deviceId "$device_id" \
    --arg iat "$iat" \
    --arg jti "$jti" \
    '{"htm": $htm, "htu": $htu, "sub": $sub, "deviceId": $deviceId, "iat": ($iat|tonumber), "jti": $jti}')
  if [[ -n "$access_token" ]]; then
    local ath
    ath=$(printf '%s' "$access_token" | openssl dgst -binary -sha256 | common::b64urlencode)
    payload=$(printf '%s' "$payload" | jq --arg ath "$ath" '. + {ath: $ath}')
  fi
  local header_json
  header_json=$(jq -cn --arg alg "$alg" --arg typ "dpop+jwt" --arg kid "$key_id" --argjson jwk "$jwk_json" '{alg:$alg,typ:$typ,kid:$kid,jwk:$jwk}')
  local header_b64 payload_b64 signature_b64
  header_b64=$(printf '%s' "$header_json" | common::b64urlencode)
  payload_b64=$(printf '%s' "$payload" | common::b64urlencode)
  signature_b64=$(common::sign_compact_jws "$alg" "$key_file" "$header_b64.$payload_b64")
  printf '%s.%s.%s\n' "$header_b64" "$payload_b64" "$signature_b64"
}

common::fetch_access_token() {
  local token_endpoint=$1
  local client_id=$2
  local client_secret=$3
  local key_file=$4
  local jwk_json=$5
  local key_id=$6
  local user_id=$7
  local device_id=$8
  local alg=$9
  local proof
  proof=$(common::create_dpop_proof "POST" "$token_endpoint" "$key_file" "$jwk_json" "$key_id" "$user_id" "$device_id" "$alg")
  curl -s -X POST \
    -H "DPoP: $proof" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "client_id=$client_id" \
    -d "client_secret=$client_secret" \
    "$token_endpoint"
}
