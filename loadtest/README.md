# Load Testing

This subproject contains the browser-side load harness used to reproduce clustered push-MFA login behavior with real SSE streams. It drives the real Keycloak login pages, opens the browser `EventSource`, approves the push challenge from the device side, and completes the browser flow through the real continuation form.

## Scope

This setup is meant to answer one question: does the real browser + SSE + device flow still hold up when requests are spread across multiple Keycloak nodes?

What it covers:

- Two Keycloak nodes
- Shared Postgres
- Shared Keycloak cache cluster via `KC_CACHE=ispn` and `KC_CACHE_STACK=jdbc-ping`
- Real realm import from `config/demo-realm.json`
- Real browser waiting pages and continuation forms
- Real SSE subscriptions on `/realms/<realm>/push-mfa/login/challenges/<cid>/events`
- Cross-node routing for browser, enrollment, and device requests

What it does not cover:

- TLS termination
- A production-grade external load balancer
- Mobile push delivery latency from FCM/APNs
- More than two Keycloak nodes

## Topology

The compose stack starts four containers:

- `postgres`
- `keycloak-1`
- `keycloak-2`
- `haproxy`

Traffic model:

- Admin setup goes through HAProxy
- Browser traffic is sent directly to both Keycloak nodes in the order configured by the harness
- Enrollment-device traffic is also spread across both nodes
- Login-device traffic is intentionally reversed across both nodes

That URI mix is deliberate. It avoids accidental stickiness and makes cross-node SSE state handling visible.

## Prerequisites

- Docker
- Java 21
- Maven

## Build

Build and install the extension first. This produces the fixed provider artifact at `target/keycloak-push-mfa-extension.jar`, which the compose stack mounts into both Keycloak nodes, and installs the extension artifact into the local Maven repository so the loadtest module can depend on it normally.

```bash
mvn install -DskipTests
```

Then build the harness:

```bash
mvn -f loadtest/pom.xml package
```

The harness can target either:

- the local compose setup in this directory
- an external Keycloak cluster or ingress endpoint

## Start The Cluster

Default ports:

- HAProxy: `18080`
- Keycloak node 1: `18081`
- Keycloak node 2: `18082`

Start the stack:

```bash
docker compose -f loadtest/docker-compose.cluster.yml up -d
```

Wait until the realm is reachable through HAProxy:

```bash
until curl -fsS http://localhost:18080/realms/demo/.well-known/openid-configuration >/dev/null; do sleep 2; done
```

If those ports are already in use, override them at startup time:

```bash
HAPROXY_PORT=18180 KC1_PORT=18181 KC2_PORT=18182 \
docker compose -f loadtest/docker-compose.cluster.yml up -d
```

Then wait on the overridden HAProxy port:

```bash
until curl -fsS http://localhost:18180/realms/demo/.well-known/openid-configuration >/dev/null; do sleep 2; done
```

## External Cluster Mode

You can also point the harness at an existing cluster instead of the local compose stack.

Required external prerequisites:

- a realm with the push-MFA extension enabled
- a browser client that supports the chosen redirect URI
- the device client credentials used by the extension
- admin credentials with enough rights to create users, reset credentials, and update the authenticator configuration

Important properties for external targets:

- `load.realm`
  Target realm name. Default: `demo`
- `load.adminRealm`
  Admin login realm. Default: `master`
- `load.adminUsername`
  Default: `admin`
- `load.adminPassword`
  Default: `admin`
- `load.adminClientId`
  Default: `admin-cli`
- `load.browserClientId`
  Browser OIDC client used for the login flow. Default: `test-app`
- `load.browserRedirectUri`
  Redirect URI for the browser client. Default: `http://localhost:8080/test-app/callback`
- `load.deviceClientId`
  Device client used for DPoP-bound token acquisition. Default: `push-device-client`
- `load.deviceClientSecret`
  Default: `device-client-secret`

Example front-door-only run against an external cluster:

```bash
mvn -f loadtest/pom.xml exec:java \
  -Dload.adminBaseUri=https://keycloak.example.com \
  -Dload.browserBaseUris=https://keycloak.example.com \
  -Dload.enrollmentDeviceBaseUris=https://keycloak.example.com \
  -Dload.deviceBaseUris=https://keycloak.example.com \
  -Dload.realm=demo \
  -Dload.adminRealm=master \
  -Dload.adminUsername=admin \
  -Dload.adminPassword=secret \
  -Dload.adminClientId=admin-cli \
  -Dload.browserClientId=test-app \
  -Dload.browserRedirectUri=https://app.example.com/callback \
  -Dload.deviceClientId=push-device-client \
  -Dload.deviceClientSecret=device-client-secret
```

Example forced cross-node run against an external cluster with two explicit node URLs:

```bash
mvn -f loadtest/pom.xml exec:java \
  -Dload.adminBaseUri=https://kc-lb.example.com \
  -Dload.browserBaseUris=https://kc-1.example.com,https://kc-2.example.com \
  -Dload.enrollmentDeviceBaseUris=https://kc-1.example.com,https://kc-2.example.com \
  -Dload.deviceBaseUris=https://kc-2.example.com,https://kc-1.example.com \
  -Dload.realm=demo \
  -Dload.browserClientId=test-app \
  -Dload.browserRedirectUri=https://app.example.com/callback \
  -Dload.deviceClientId=push-device-client \
  -Dload.deviceClientSecret=device-client-secret
```

## HAProxy Notes

HAProxy is intentionally minimal. It exists to give the cluster one shared front door for admin setup and realistic forwarded headers.

Important details:

- `X-Forwarded-Proto` is fixed to `http`
- `X-Forwarded-Host` uses only the host portion of the incoming header
- `X-Forwarded-Port` uses the explicit external port from the incoming header

That host/port split matters. If forwarded headers are wrong, Keycloak can generate invalid frontend URLs and OIDC discovery through HAProxy can fail.

## Why The Harness Does Not Use HAProxy For Every Request

The harness does not send browser and device traffic through HAProxy by default because the goal of this setup is to exercise cross-node state handling deliberately, not just "whatever the load balancer happened to do".

Direct node URIs give the harness two useful properties:

- It can force browser and device actions for the same login onto different nodes.
- It can reproduce non-sticky routing consistently instead of depending on whichever backend HAProxy happens to pick next.

If all traffic goes through HAProxy, that is still a valid test, but it answers a slightly different question:

- "Does the system work behind this balancer?"

rather than:

- "Does the push-MFA flow still work when the browser, SSE reconnect, and device approval bounce across nodes?"

If you want the front-door-only mode, point every base URI at HAProxy:

```bash
mvn -f loadtest/pom.xml exec:java \
  -Dload.adminBaseUri=http://localhost:18080 \
  -Dload.browserBaseUris=http://localhost:18080 \
  -Dload.enrollmentDeviceBaseUris=http://localhost:18080 \
  -Dload.deviceBaseUris=http://localhost:18080
```

That mode is useful as an additional sanity check, but it is less targeted for uncovering cross-node SSE and auth-session issues.

## Run The Browser SSE Harness

Default run:

```bash
mvn -f loadtest/pom.xml exec:java
```

Example higher-rate run on the default ports:

```bash
mvn -f loadtest/pom.xml exec:java \
  -Dload.ratePerSecond=30 \
  -Dload.durationSeconds=30 \
  -Dload.userCount=30 \
  -Dload.workerThreads=40
```

Example higher-rate run on the alternate `18180/18181/18182` ports:

```bash
mvn -f loadtest/pom.xml exec:java \
  -Dload.adminBaseUri=http://localhost:18180 \
  -Dload.browserBaseUris=http://localhost:18181,http://localhost:18182 \
  -Dload.enrollmentDeviceBaseUris=http://localhost:18181,http://localhost:18182 \
  -Dload.deviceBaseUris=http://localhost:18182,http://localhost:18181 \
  -Dload.ratePerSecond=30 \
  -Dload.durationSeconds=30 \
  -Dload.userCount=30 \
  -Dload.workerThreads=40
```

Useful properties:

- `load.adminBaseUri`
  Default: `http://localhost:18080`
- `load.browserBaseUris`
  Default: `http://localhost:18081,http://localhost:18082`
- `load.enrollmentDeviceBaseUris`
  Default: `http://localhost:18081,http://localhost:18082`
- `load.deviceBaseUris`
  Default: `http://localhost:18082,http://localhost:18081`
- `load.userPrefix`
  Default: `load-user-`
- `load.password`
  Default: `load-test`
- `load.realm`
  Default: `demo`
- `load.adminRealm`
  Default: `master`
- `load.adminUsername`
  Default: `admin`
- `load.adminPassword`
  Default: `admin`
- `load.adminClientId`
  Default: `admin-cli`
- `load.browserClientId`
  Default: `test-app`
- `load.browserRedirectUri`
  Default: `http://localhost:8080/test-app/callback`
- `load.deviceClientId`
  Default: `push-device-client`
- `load.deviceClientSecret`
  Default: `device-client-secret`
- `load.ratePerSecond`
  Default: `10`
- `load.durationSeconds`
  Default: `30`
- `load.userCount`
  Default: `30`
- `load.workerThreads`
  Default: `20`

## What The Harness Actually Does

For each test user, the harness:

1. Creates or resets the user through the admin API.
2. Enrolls one device by driving the real browser enrollment page and the real device enrollment endpoint.
3. Resets the browser session so the actual load run starts clean.

For each login attempt, the harness:

1. Opens the real browser login page.
2. Submits username/password.
3. Extracts the login challenge and SSE URL from the waiting page.
4. Opens a real SSE client against that URL.
5. Approves the challenge from the device side.
6. Waits for `APPROVED` on the SSE stream.
7. Submits the waiting form back to Keycloak to finish the flow.

This means the load test exercises the real browser-side waiting path, not a shortcut API-only approximation.

## Observability

Useful commands while the stack is running:

Show cluster logs:

```bash
docker compose -f loadtest/docker-compose.cluster.yml logs -f keycloak-1 keycloak-2 haproxy
```

Check the imported realm through HAProxy:

```bash
curl -fsS http://localhost:18080/realms/demo/.well-known/openid-configuration
```

Check for server warnings and errors from the recent run:

```bash
docker compose -f loadtest/docker-compose.cluster.yml logs --since 2m keycloak-1 keycloak-2 | rg "\\] ERROR |\\] WARN "
```

## Interpreting Results

The harness prints:

- attempts started, completed, succeeded, and failed
- user-pool timeouts
- observed throughput
- latency percentiles
- top failure categories

Treat those numbers as environment-specific. Results depend on the machine, Docker runtime, JVM, Keycloak version, and whether you route traffic directly to nodes or through HAProxy.

If you want to keep a run for later comparison, redirect the output into `target/loadtest/`:

```bash
mvn -f loadtest/pom.xml exec:java \
  -Dload.ratePerSecond=30 \
  -Dload.durationSeconds=30 \
  -Dload.userCount=30 \
  -Dload.workerThreads=40 \
  > target/loadtest/example-run.out 2>&1
```

## Stop The Cluster

```bash
docker compose -f loadtest/docker-compose.cluster.yml down -v
```
