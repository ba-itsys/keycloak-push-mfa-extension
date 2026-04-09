#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REALM="${LOAD_REALM:-demo}"
ADMIN_BASE_URI="${LOAD_ADMIN_BASE_URI:-http://host.docker.internal:18080}"

exec docker run --rm -i \
  -e K6_BROWSER_HEADLESS="${K6_BROWSER_HEADLESS:-true}" \
  -e LOAD_ADMIN_BASE_URI="${ADMIN_BASE_URI}" \
  -e LOAD_BROWSER_BASE_URIS="${LOAD_BROWSER_BASE_URIS:-http://host.docker.internal:18081,http://host.docker.internal:18082}" \
  -e LOAD_ENROLLMENT_DEVICE_BASE_URIS="${LOAD_ENROLLMENT_DEVICE_BASE_URIS:-http://host.docker.internal:18081,http://host.docker.internal:18082}" \
  -e LOAD_DEVICE_BASE_URIS="${LOAD_DEVICE_BASE_URIS:-http://host.docker.internal:18082,http://host.docker.internal:18081}" \
  -e LOAD_REALM="${REALM}" \
  -e LOAD_ADMIN_REALM="${LOAD_ADMIN_REALM:-master}" \
  -e LOAD_ADMIN_USERNAME="${LOAD_ADMIN_USERNAME:-admin}" \
  -e LOAD_ADMIN_PASSWORD="${LOAD_ADMIN_PASSWORD:-admin}" \
  -e LOAD_ADMIN_CLIENT_ID="${LOAD_ADMIN_CLIENT_ID:-admin-cli}" \
  -e LOAD_BROWSER_CLIENT_ID="${LOAD_BROWSER_CLIENT_ID:-test-app}" \
  -e LOAD_BROWSER_REDIRECT_URI="${LOAD_BROWSER_REDIRECT_URI:-}" \
  -e LOAD_DEVICE_CLIENT_ID="${LOAD_DEVICE_CLIENT_ID:-push-device-client}" \
  -e LOAD_DEVICE_CLIENT_SECRET="${LOAD_DEVICE_CLIENT_SECRET:-device-client-secret}" \
  -e LOAD_USER_PREFIX="${LOAD_USER_PREFIX:-load-user-}" \
  -e LOAD_PASSWORD="${LOAD_PASSWORD:-load-test}" \
  -e LOAD_USER_COUNT="${LOAD_USER_COUNT:-40}" \
  -e LOAD_RATE_PER_SECOND="${LOAD_RATE_PER_SECOND:-10}" \
  -e LOAD_DURATION_SECONDS="${LOAD_DURATION_SECONDS:-30}" \
  -e LOAD_PRE_ALLOCATED_VUS="${LOAD_PRE_ALLOCATED_VUS:-40}" \
  -e LOAD_MAX_VUS="${LOAD_MAX_VUS:-40}" \
  -e LOAD_AUTH_TIMEOUT_MS="${LOAD_AUTH_TIMEOUT_MS:-10000}" \
  -e LOAD_LOGIN_COMPLETE_TIMEOUT_MS="${LOAD_LOGIN_COMPLETE_TIMEOUT_MS:-20000}" \
  -e LOAD_CONFIGURE_PUSH_MFA="${LOAD_CONFIGURE_PUSH_MFA:-true}" \
  -e LOAD_INSECURE_TLS="${LOAD_INSECURE_TLS:-false}" \
  -v "${ROOT_DIR}/loadtest:/loadtest:ro" \
  "${K6_IMAGE:-grafana/k6:master-with-browser}" \
  run /loadtest/push-mfa-browser.js
