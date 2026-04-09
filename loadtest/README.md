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
- `LOAD_RATE_PER_SECOND`
  Default: `10`
- `LOAD_DURATION_SECONDS`
  Default: `30`
- `LOAD_PRE_ALLOCATED_VUS`
  Default: `40`
- `LOAD_MAX_VUS`
  Default: `40`
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
4. Creates or updates the load users.
5. Clears push credentials and sessions for those users.
6. Pre-enrolls one device per user before the measured load starts.

Per VU iteration:

1. Opens a real Chromium page for login.
2. Submits username and password.
3. Waits on the real login wait page.
4. Approves the challenge from the pre-enrolled device side with DPoP.
5. Lets the page's own `EventSource` logic receive the SSE update and auto-submit.
6. Waits for the browser to reach the configured callback URL with an authorization code.

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
