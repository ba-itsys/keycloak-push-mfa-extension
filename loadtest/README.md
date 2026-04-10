# Load Testing

This directory contains the k6-based loadtest setup for the push-MFA browser flow.

The loadtest uses:

- protocol-level HTTP for admin setup, enrollment, and device-side approval
- the k6 browser module for the login wait page, so the page's own `EventSource` logic is exercised
- the official `grafana/k6:master-with-browser` image by default

## Scope

The goal of this setup is to test the real clustered login flow, including browser-side SSE behavior, under load.

What it covers:

- real login pages
- real browser-side SSE handling
- real device challenge approval flow
- clustered Keycloak nodes with shared cache state
- both front-door-only and forced cross-node request patterns

What it does not cover:

- mobile push delivery latency from FCM or APNs
- a distributed load-generator farm
- more than two Keycloak nodes in the local compose setup

## Files

- [push-mfa-browser.js](/Users/dominik/projects/keycloak-push-mfa-poc/loadtest/push-mfa-browser.js)
  k6 scenario script
- [run-k6-browser.sh](/Users/dominik/projects/keycloak-push-mfa-poc/loadtest/run-k6-browser.sh)
  wrapper around the official browser-enabled k6 image
- [docker-compose.cluster.yml](/Users/dominik/projects/keycloak-push-mfa-poc/loadtest/docker-compose.cluster.yml)
  local two-node Keycloak cluster
- [haproxy.cfg](/Users/dominik/projects/keycloak-push-mfa-poc/loadtest/haproxy.cfg)
  minimal front door for the local cluster

## Local Cluster

The local compose stack starts:

- `postgres`
- `keycloak-1`
- `keycloak-2`
- `haproxy`

Default ports:

- HAProxy: `18080`
- Keycloak node 1: `18081`
- Keycloak node 2: `18082`

Start it:

```bash
docker compose -f loadtest/docker-compose.cluster.yml up -d
```

Wait until the realm is reachable:

```bash
until curl -fsS http://localhost:18080/realms/demo/.well-known/openid-configuration >/dev/null; do sleep 2; done
```

For the default local setup, the k6 container reaches Keycloak over plain HTTP via `host.docker.internal`. That means the admin password-grant token request against `master` also comes in over HTTP. If your local stack still has `master.sslRequired=external`, relax it once before running the loadtest:

```bash
docker compose -f loadtest/docker-compose.cluster.yml exec -T keycloak-1 \
  /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 --realm master --user admin --password admin

docker compose -f loadtest/docker-compose.cluster.yml exec -T keycloak-1 \
  /opt/keycloak/bin/kcadm.sh update realms/master -s sslRequired=NONE
```

If those ports are busy, use alternates:

```bash
HAPROXY_PORT=18180 KC1_PORT=18181 KC2_PORT=18182 \
docker compose -f loadtest/docker-compose.cluster.yml up -d
```

## Why Two Routing Modes Exist

There are two useful ways to drive the cluster:

- front-door-only:
  all browser and device traffic goes through HAProxy or another ingress
- forced cross-node:
  browser and device requests are pointed at explicit nodes so cross-node behavior is guaranteed instead of probabilistic

Round-robin HAProxy is valid and simpler. It is good for "does this work behind the balancer?".

Explicit node URIs are more targeted. They are useful when you want to force:

- browser login on one node
- device approval on another node
- reconnects and continuation on different nodes

## Running The k6 Loadtest

The wrapper uses Docker and the official browser-enabled k6 image, so you do not need a local k6 install.

Default local run:

```bash
./loadtest/run-k6-browser.sh
```

Example higher-rate local run:

```bash
LOAD_RATE_PER_SECOND=30 \
LOAD_DURATION_SECONDS=30 \
LOAD_PRE_ALLOCATED_VUS=40 \
LOAD_MAX_VUS=40 \
LOAD_USER_COUNT=40 \
./loadtest/run-k6-browser.sh
```

Example enrollment-only run at 30 enrollments/s:

```bash
LOAD_TEST_MODE=enrollment \
LOAD_RATE_PER_SECOND=30 \
LOAD_DURATION_SECONDS=30 \
LOAD_PRE_ALLOCATED_VUS=40 \
LOAD_MAX_VUS=40 \
LOAD_USER_COUNT=940 \
./loadtest/run-k6-browser.sh
```

Example mixed run with concurrent login and enrollment traffic:

```bash
LOAD_TEST_MODE=mixed \
LOAD_MOBILE_MOCK_BASE_URI=http://host.docker.internal:3001 \
LOAD_LOGIN_RATE_PER_SECOND=20 \
LOAD_ENROLLMENT_RATE_PER_SECOND=5 \
LOAD_DURATION_SECONDS=30 \
LOAD_LOGIN_PRE_ALLOCATED_VUS=20 \
LOAD_LOGIN_MAX_VUS=30 \
LOAD_ENROLLMENT_PRE_ALLOCATED_VUS=10 \
LOAD_ENROLLMENT_MAX_VUS=20 \
LOAD_LOGIN_USER_COUNT=40 \
LOAD_ENROLLMENT_USER_COUNT=170 \
./loadtest/run-k6-browser.sh
```

If k6's built-in WebCrypto/browser combination becomes the bottleneck during login-heavy runs, start the mobile mock and let it perform the device-side signing instead:

```bash
cd mock/mobile
npm install
npm run build
REALM_BASE=http://localhost:18080/realms/demo npm run start
```

Example pre-seeding a reusable enrollment pool once, then running against that pool without repeating setup:

```bash
LOAD_TEST_MODE=seed-enrollment \
LOAD_ENROLLMENT_USER_COUNT=2000 \
LOAD_ENROLLMENT_USER_OFFSET=1000 \
./loadtest/run-k6-browser.sh

LOAD_TEST_MODE=enrollment \
LOAD_SKIP_ENROLLMENT_USER_PREP=true \
LOAD_ENROLLMENT_USER_OFFSET=1000 \
LOAD_USER_COUNT=200 \
LOAD_RATE_PER_SECOND=30 \
LOAD_DURATION_SECONDS=30 \
./loadtest/run-k6-browser.sh
```

Example higher-rate local run against alternate ports:

```bash
LOAD_ADMIN_BASE_URI=http://host.docker.internal:18180 \
LOAD_BROWSER_BASE_URIS=http://host.docker.internal:18181,http://host.docker.internal:18182 \
LOAD_ENROLLMENT_DEVICE_BASE_URIS=http://host.docker.internal:18181,http://host.docker.internal:18182 \
LOAD_DEVICE_BASE_URIS=http://host.docker.internal:18182,http://host.docker.internal:18181 \
LOAD_RATE_PER_SECOND=30 \
LOAD_DURATION_SECONDS=30 \
LOAD_PRE_ALLOCATED_VUS=40 \
LOAD_MAX_VUS=40 \
LOAD_USER_COUNT=40 \
./loadtest/run-k6-browser.sh
```

The wrapper defaults use `host.docker.internal` because the browser-enabled k6 process runs inside Docker.

## External Cluster Mode

You can point the same script at an external Keycloak cluster.

Required inputs:

- admin base URI
- target realm
- admin credentials
- browser client id and redirect URI
- device client id and secret

Example front-door-only run:

```bash
LOAD_ADMIN_BASE_URI=https://keycloak.example.com \
LOAD_BROWSER_BASE_URIS=https://keycloak.example.com \
LOAD_ENROLLMENT_DEVICE_BASE_URIS=https://keycloak.example.com \
LOAD_DEVICE_BASE_URIS=https://keycloak.example.com \
LOAD_REALM=demo \
LOAD_ADMIN_REALM=master \
LOAD_ADMIN_USERNAME=admin \
LOAD_ADMIN_PASSWORD=secret \
LOAD_BROWSER_CLIENT_ID=test-app \
LOAD_BROWSER_REDIRECT_URI=https://keycloak.example.com/test-app/callback \
LOAD_DEVICE_CLIENT_ID=push-device-client \
LOAD_DEVICE_CLIENT_SECRET=device-client-secret \
./loadtest/run-k6-browser.sh
```

Example forced cross-node run:

```bash
LOAD_ADMIN_BASE_URI=https://kc-lb.example.com \
LOAD_BROWSER_BASE_URIS=https://kc-1.example.com,https://kc-2.example.com \
LOAD_ENROLLMENT_DEVICE_BASE_URIS=https://kc-1.example.com,https://kc-2.example.com \
LOAD_DEVICE_BASE_URIS=https://kc-2.example.com,https://kc-1.example.com \
LOAD_REALM=demo \
LOAD_BROWSER_CLIENT_ID=test-app \
LOAD_BROWSER_REDIRECT_URI=https://kc-lb.example.com/test-app/callback \
LOAD_DEVICE_CLIENT_ID=push-device-client \
LOAD_DEVICE_CLIENT_SECRET=device-client-secret \
./loadtest/run-k6-browser.sh
```

If the external cluster is already configured the way you want, you can skip the admin-side authenticator adjustments:

```bash
LOAD_CONFIGURE_PUSH_MFA=false ./loadtest/run-k6-browser.sh
```

## Important Environment Variables

- `LOAD_ADMIN_BASE_URI`
  Base URI used for admin setup and default redirect generation
- `LOAD_BROWSER_BASE_URIS`
  Comma-separated browser target URIs
- `LOAD_ENROLLMENT_DEVICE_BASE_URIS`
  Comma-separated device URIs used during enrollment
- `LOAD_DEVICE_BASE_URIS`
  Comma-separated device URIs used during login approval
- `LOAD_REALM`
  Default: `demo`
- `LOAD_ADMIN_REALM`
  Default: `master`
- `LOAD_ADMIN_USERNAME`
  Default: `admin`
- `LOAD_ADMIN_PASSWORD`
  Default: `admin`
- `LOAD_ADMIN_CLIENT_ID`
  Default: `admin-cli`
- `LOAD_BROWSER_CLIENT_ID`
  Default: `test-app`
- `LOAD_BROWSER_REDIRECT_URI`
  Default: browser target base URI + `/${LOAD_BROWSER_CLIENT_ID}/callback`
- `LOAD_DEVICE_CLIENT_ID`
  Default: `push-device-client`
- `LOAD_DEVICE_CLIENT_SECRET`
  Default: `device-client-secret`
- `LOAD_USER_PREFIX`
  Default: `load-user-`
- `LOAD_PASSWORD`
  Default: `load-test`
- `LOAD_USER_COUNT`
  Default: `40`
- `LOAD_TEST_MODE`
  Default: `login` (`enrollment`, `mixed`, and `seed-enrollment` are also supported)
- `LOAD_RATE_PER_SECOND`
  Default: `10`
- `LOAD_LOGIN_RATE_PER_SECOND`
  Default: `LOAD_RATE_PER_SECOND`
- `LOAD_ENROLLMENT_RATE_PER_SECOND`
  Default: `LOAD_RATE_PER_SECOND`
- `LOAD_DURATION_SECONDS`
  Default: `30`
- `LOAD_PRE_ALLOCATED_VUS`
  Default: `40`
- `LOAD_MAX_VUS`
  Default: `40`
- `LOAD_LOGIN_PRE_ALLOCATED_VUS`
  Default: `LOAD_PRE_ALLOCATED_VUS`
- `LOAD_LOGIN_MAX_VUS`
  Default: `LOAD_MAX_VUS`
- `LOAD_ENROLLMENT_PRE_ALLOCATED_VUS`
  Default: `LOAD_PRE_ALLOCATED_VUS`
- `LOAD_ENROLLMENT_MAX_VUS`
  Default: `LOAD_MAX_VUS`
- `LOAD_LOGIN_USER_COUNT`
  Default: `LOAD_USER_COUNT`
- `LOAD_ENROLLMENT_USER_COUNT`
  Default: `LOAD_USER_COUNT`
- `LOAD_LOGIN_USER_OFFSET`
  Default: `0`
- `LOAD_ENROLLMENT_USER_OFFSET`
  Default: next range after the login pool in mixed mode, otherwise `0`
- `LOAD_SKIP_ENROLLMENT_USER_PREP`
  Default: `false` (skip per-run admin setup for a previously seeded fresh enrollment pool)
- `LOAD_CONFIGURE_PUSH_MFA`
  Default: `true`
- `LOAD_INSECURE_TLS`
  Default: `false`

## What The Script Does

Setup phase:

1. Logs in to the admin API.
2. Optionally sets the push authenticator to:
   `userVerification=none`, `autoAddRequiredAction=true`, `waitChallengeEnabled=false`
3. If `LOAD_BROWSER_CLIENT_ID=test-app`, widens that client's redirect URIs to the target callback URLs.
4. Creates or updates the configured login and enrollment user pools.
5. Clears push credentials and sessions for those users unless the enrollment pool is marked as pre-seeded.
6. Pre-enrolls one device per login user before the measured load starts.

Per VU iteration:

1. Login mode: opens a real Chromium page, completes the push challenge, and waits for the callback redirect with an authorization code.
2. Enrollment mode: performs the full browser login plus device enrollment flow over HTTP for a fresh user.
3. Mixed mode: runs both flows concurrently with separate rates and user pools.
4. Seed-enrollment mode: prepares a reusable enrollment pool and exits without measured traffic.

## Interpreting Results

k6 prints the standard summary:

- iterations
- iteration rate
- browser and HTTP timings
- checks and failures

Treat the numbers as environment-specific. They depend on:

- the machine running k6
- Docker runtime overhead
- browser mode overhead
- Keycloak topology
- whether traffic is front-door-only or forced across nodes

## Stop The Local Cluster

```bash
docker compose -f loadtest/docker-compose.cluster.yml down -v
```
