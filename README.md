# Keycloak Push MFA Extension

A Keycloak extension that adds push-based multi-factor authentication, similar to passkey primitives.

## Table of Contents

- [Quick Start](#quick-start)
- [High Level Flow](#high-level-flow) — Visual overview of enrollment and login
- [Keycloak Concepts](#keycloak-concepts-quick-primer) — Quick primer for Keycloak newcomers
- [Setup Guide](#setup-guide) — Step-by-step configuration instructions
- [Flow Details](#flow-details) — Technical details of each phase
- [Custom Keycloak APIs](#custom-keycloak-apis) — REST endpoints for mobile apps
- [Configuration Reference](#configuration-reference) — All configuration options
- [App Implementation Notes](#app-implementation-notes) — Guide for mobile app developers
- [Push Notification SPI](#push-notification-spi) — Implementing custom push providers
- [Push MFA Event SPI](#push-mfa-event-spi) — Reacting to push MFA events
- [Wait Challenge Rate Limiting](#wait-challenge-rate-limiting) — Exponential backoff for unapproved challenges
- [Customizing the UI](#customizing-the-keycloak-ui) — Theme customization
- [Security](#security-guarantees-and-mobile-obligations) — Security model and requirements
- [Mobile Mock](#mobile-mock-for-push-mfa-enrollment-and-login) — Testing without a real mobile app
- [Troubleshooting](#troubleshooting) — Common issues and solutions

---

## Quick Start

### Using Maven (recommended)

Add the dependency to your project:

```xml
<dependency>
    <groupId>de.arbeitsagentur.opdt</groupId>
    <artifactId>keycloak-push-mfa-extension</artifactId>
    <version>1.3.1</version>
</dependency>
```

Copy the JAR to Keycloak's `providers/` directory and restart Keycloak.

### Building from Source

```bash
# Build the provider
mvn -DskipTests package

# Run Keycloak with the demo realm
docker compose up
```

- **Keycloak Admin Console:** http://localhost:8080 (login: `admin` / `admin`)
- **Demo Realm:** `demo` with test user `test` / `test`
- **Demo Configuration:** See `config/demo-realm.json` for a working example

## Introduction

This project extends Keycloak with a push-style second factor that mimics passkey primitives. After initial enrollment, the mobile app never receives the real user identifier from Keycloak; instead, it works with a credential id that only the app can map back to the real user. Everything is implemented with standard Keycloak SPIs plus a small JAX-RS resource exposed under `/realms/<realm>/push-mfa`.

## High Level Flow

```mermaid
sequenceDiagram
    autonumber
    participant Browser as User / Browser
    participant Keycloak as Keycloak Server
    participant Provider as Push Provider (FCM/APNs)
    participant Mobile as Mobile App

    Note over Browser, Mobile: **Phase 1: Enrollment (Register Push MFA Device)**
    
    Browser->>Keycloak: Login & Trigger Enrollment
    Keycloak-->>Browser: Render QR Code & Start SSE Listener
    
    par Parallel Actions
        Browser->>Keycloak: SSE Connection (Watch Status)
        Browser->>Mobile: Scan QR Code
    end

    Note over Mobile: Verify Token & Generate User Key Pair
    
    Mobile->>Keycloak: POST /enroll/complete
    Note right of Mobile: Payload: Device JWT + Public JWK<br/>Signed with new Device Private Key

    Keycloak->>Keycloak: Verify Signature & Store Device Credential
    Keycloak-->>Browser: SSE Event: { status: "APPROVED" }
    Browser->>Keycloak: Auto-Submit Form (Enrollment Complete)

    Note over Browser, Mobile: **Phase 2: Login (Push MFA Confirmation)**

    Browser->>Keycloak: Login (Username/Password)
    Keycloak->>Keycloak: Generate Challenge & ConfirmToken
    
    par Parallel Actions
        Keycloak-->>Browser: Render "Waiting for approval..." Page
        Browser->>Keycloak: SSE Connection (Watch Challenge)
        Keycloak->>Provider: Send Push Notification
        Note right of Keycloak: Payload: ConfirmToken<br/>(Credential ID, ChallengeID)
    end

    Provider->>Mobile: Deliver Push Notification
    
    Mobile->>Mobile: Decrypt Token & Resolve User ID
    Mobile-->>Browser: (User Prompt: Approve?)
    Browser-->>Mobile: User Taps "Approve"

    Mobile->>Keycloak: POST /login/challenges/{cid}/respond
    Note right of Mobile: Payload: LoginToken (Action: Approve)<br/>Auth: DPoP Header + Access Token<br/>Signed with Device Private Key

    Keycloak->>Keycloak: Verify DPoP, Signature & Challenge ID
    Keycloak-->>Browser: SSE Event: { status: "APPROVED" }
    Browser->>Keycloak: Auto-Submit Form (Login Success)
```

## Keycloak Concepts (Quick Primer)

If you're new to Keycloak, here's a quick overview of the concepts used in this extension:

| Concept | What it is | How it's used here |
|---------|-----------|-------------------|
| **Realm** | An isolated security domain in Keycloak. Each realm has its own users, clients, and settings. | The demo uses a realm called `demo`. |
| **Authentication Flow** | A sequence of steps a user must complete to log in. Flows are made up of "executions" (authenticators). | We create `browser-push-flow` with username/password + push MFA. |
| **Authenticator** | A single step in an authentication flow (e.g., password check, OTP verification). | `push-mfa-authenticator` sends push notifications and waits for approval. |
| **Required Action** | A one-time task a user must complete (e.g., reset password, configure OTP). | `push-mfa-register` handles device enrollment via QR code. |
| **Client** | An application that uses Keycloak for authentication. | `test-app` (web app) and `push-device-client` (mobile device API). |

## Setup Guide

This section walks you through setting up Push MFA in your Keycloak instance. The demo realm (`config/demo-realm.json`) provides a working example of all these configurations.

### Step 1: Deploy the Extension

1. Build the provider:
   ```bash
   mvn -DskipTests package
   ```

2. Copy the JAR to Keycloak's `providers/` directory, or use Docker Compose (which does this automatically):
   ```bash
   docker compose up
   ```

### Step 2: Enable the Required Action (for Enrollment)

The **Required Action** allows users to enroll their mobile device by scanning a QR code.

**Via Admin Console:**
1. Go to **Authentication → Required Actions**
2. Find `Register Push MFA device` in the list
3. Toggle **Enabled** to ON
4. (Optional) Toggle **Default Action** to ON if you want all users to enroll automatically

**What the demo realm does** (see `config/demo-realm.json:72-81`):
```json
"requiredActions": [
  {
    "alias": "push-mfa-register",
    "name": "Register Push MFA device",
    "providerId": "push-mfa-register",
    "enabled": true,
    "defaultAction": false,  // Set to true to force enrollment for all users
    "priority": 100
  }
]
```

**To trigger enrollment for a specific user:**
1. Go to **Users → [select user] → Required Actions**
2. Add `Register Push MFA device` to the user's pending actions

### Step 3: Create an Authentication Flow (for Login)

The **Authenticator** handles the push notification during login. You need to add it to an authentication flow.

**Via Admin Console:**
1. Go to **Authentication → Flows**
2. Click **Create flow** or duplicate the built-in `browser` flow
3. Add these executions in order:
   - `Cookie` (ALTERNATIVE) — allows session cookies to skip login
   - `Identity Provider Redirector` (ALTERNATIVE) — for social/federated login
   - A **sub-flow** (ALTERNATIVE) containing:
     - `Username Password Form` (REQUIRED)
     - `Push MFA Authenticator` (REQUIRED)

**What the demo realm does** (see `config/demo-realm.json:82-131`):

The demo creates two flows:

1. **`browser-push-flow`** (top-level flow):
   ```
   ├── Cookie                          [ALTERNATIVE]
   ├── Identity Provider Redirector    [ALTERNATIVE]
   └── browser-push-forms (sub-flow)   [ALTERNATIVE]
   ```

2. **`browser-push-forms`** (sub-flow):
   ```
   ├── Username Password Form          [REQUIRED]
   └── Push MFA Authenticator          [REQUIRED]
   ```

The sub-flow pattern ensures that push MFA only triggers after successful password authentication.

### Step 4: Bind the Flow to the Realm

**Via Admin Console:**
1. Go to **Authentication → Flows**
2. Click the **⋯** menu next to your flow
3. Select **Bind flow** → **Browser flow**

Or go to **Realm Settings → Authentication** and set **Browser flow** to your custom flow.

**What the demo realm does** (see `config/demo-realm.json:9`):
```json
"browserFlow": "browser-push-flow"
```

### Step 5: Create the Device Client

The mobile app needs a confidential client to obtain DPoP-bound access tokens.

**Via Admin Console:**
1. Go to **Clients → Create client**
2. Set:
   - **Client ID**: `push-device-client`
   - **Client authentication**: ON
   - **Service accounts roles**: ON
   - **Standard flow**: OFF
   - **Direct access grants**: OFF
3. In the **Credentials** tab, note the client secret
4. In the **Advanced** tab, enable **DPoP bound access tokens**

**What the demo realm does** (see `config/demo-realm.json:24-36`):
```json
{
  "clientId": "push-device-client",
  "publicClient": false,
  "serviceAccountsEnabled": true,
  "secret": "device-client-secret",
  "attributes": {
    "dpopBoundAccessTokens": "true"
  }
}
```

### Step 6: Configure the Authenticator (Optional)

To customize the authenticator behavior:

**Via Admin Console:**
1. Go to **Authentication → Flows**
2. Open your flow and find `Push MFA Authenticator`
3. Click the **⚙️ gear icon** to configure:
   - **Login challenge TTL** — how long the push notification is valid
   - **Max pending challenges** — concurrent logins per user
   - **User verification** — `none`, `number-match`, or `pin`

**Via CLI:**
```bash
# Get the execution ID first
EXEC_ID=$(kcadm.sh get authentication/flows/browser-push-forms/executions -r demo \
  --fields id,displayName | jq -r '.[] | select(.displayName=="Push MFA Authenticator") | .id')

# Update configuration
kcadm.sh create authentication/executions/$EXEC_ID/config -r demo \
  -s alias=push-mfa-config \
  -s config.loginChallengeTtlSeconds=180 \
  -s config.userVerification=number-match
```

### Step 7: Configure the Required Action (Optional)

To customize enrollment behavior:

**Via Admin Console:**
1. Go to **Authentication → Required Actions**
2. Click **Configure** next to `Register Push MFA device`
3. Set:
   - **Enrollment challenge TTL** — how long the QR code is valid
   - **App universal link** — deep link scheme for your mobile app

**Via CLI:**
```bash
kcadm.sh update authentication/required-actions/push-mfa-register -r demo \
  -s "config.enrollmentChallengeTtlSeconds=300" \
  -s "config.enrollmentAppUniversalLink=myapp://enroll"
```

---

## Flow Details

The following sections provide detailed technical information about each phase of the enrollment and login flows.

### Enrollment Flow

1. **Enrollment challenge (RequiredAction):** Keycloak renders a QR code that encodes the realm-signed `enrollmentToken` (the default theme emits `my-secure://enroll?token=<enrollmentToken>`, but you can change the URI scheme/payload in your own theme or override the server-side prefix via `--spi-required-action-push-mfa-register-app-uri-prefix=...`). The token is a JWT signed with the realm key and contains user id (`sub`), username, `enrollmentId`, and a Base64URL nonce.

   ```json
   {
     "_comment": "enrollmentToken payload (realm -> device)",
     "iss": "http://localhost:8080/realms/demo",
     "aud": "demo",
     "typ": "push-enroll-challenge",
     "sub": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
     "username": "test",
     "realm": "demo",
     "enrollmentId": "b15ef7f2-494c-4f03-a9b4-5b7eb4a71caa",
     "nonce": "JYlLk0d9h9zGN7kMd8n5Vw",
     "exp": 1731403200,
     "iat": 1731402900
   }
   ```

2. **Device enrollment response:** The app verifies the token using the realm JWKS, generates a user key pair and `kid`, and posts a JWT back to Keycloak that echoes the nonce and enrollment id, embeds the JWK under `cnf.jwk`, and introduces a credential id (passkey-style). Supply a `deviceId` only when you allow the same user to enroll multiple devices; otherwise use a stable value (for example `primary-device`) so the credential still has a predictable id. The JWT header uses the same `kid` that appears under `cnf.jwk`:

   Header:

   ```json
   {
     "alg": "RS256",
     "typ": "JWT",
     "kid": "user-key-31c3"
   }
   ```

   Payload:

   ```json
   {
     "_comment": "credential enrollment payload (device -> realm)",
     "enrollmentId": "b15ef7f2-494c-4f03-a9b4-5b7eb4a71caa",
     "nonce": "JYlLk0d9h9zGN7kMd8n5Vw",
     "sub": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
     "deviceType": "ios",
     "pushProviderId": "mock-provider-token",
     "pushProviderType": "log",
     "credentialId": "credential-bf7a9f52",
     "deviceId": "device-3d7a4e65-9bd6-4df3-9c7d-2b3e0ce9e1a5",
     "deviceLabel": "Demo Phone",
     "cnf": {
       "jwk": {
         "kty": "RSA",
         "n": "uVvbx3-...",
         "e": "AQAB",
         "alg": "RS256",
         "use": "sig",
         "kid": "user-key-31c3"
       }
     },
     "iat": 1731402910,
     "exp": 1731403200
   }
   ```

3. **Confirm token delivery:** Every login creates a fresh push challenge. Keycloak signs a `confirmToken` using the realm key and displays/logs it. This token is what would be sent via your push provider (Firebase/FCM in the demo implementation): it contains only the credential id (`credId`), the challenge id (`cid`), and the numeric message `typ`/`ver` identifiers so the provider learns nothing about the real user or whether the login ultimately succeeds. After receiving a push, the device should call `/realms/demo/push-mfa/login/pending` to fetch the username + client metadata to display in its approval prompt (and optional user-verification metadata if enabled).

   ```json
   {
     "_comment": "confirmToken payload (realm -> device via push provider such as Firebase/FCM)",
     "iss": "http://localhost:8080/realms/demo",
     "credId": "credential-bf7a9f52",
     "typ": 1,
     "ver": 1,
     "cid": "1a6d6a0b-3385-4772-8eb8-0d2f4dbd25a4",
     "iat": 1731402960,
     "exp": 1731403260
   }
   ```

4. **Login approval:** The device looks up the confirm token’s `credId` (credential id), resolves it to the real Keycloak user id in its secure storage, and signs a JWT (`loginToken`) with the same key pair from enrollment. The payload echoes the challenge id (`cid`), the `credId`, and the desired `action` (`approve`/`deny`) so Keycloak can fully trust the intent because it is covered by the user key signature (no nonce is needed because possession of the key already proves authenticity, and `cid` is unguessable). If user verification is enabled, the device must include the selected number / entered PIN as `userVerification` (as a JSON string; preserve leading zeros) when approving (deny works without it).

  ```json
  {
     "_comment": "login approval payload (device -> realm)",
      "cid": "1a6d6a0b-3385-4772-8eb8-0d2f4dbd25a4",
      "credId": "credential-bf7a9f52",
      "deviceId": "device-3d7a4e65-9bd6-4df3-9c7d-2b3e0ce9e1a5",
      "action": "approve",
      "userVerification": "42",
      "exp": 1731403020
    }
   ```

   See [DPoP Authentication](#dpop-authentication) for the proof format and how access tokens are obtained.

5. **Browser wait (SSE):** The Keycloak login UI now opens a server-sent events (SSE) stream for the login challenge. Once the SSE status switches away from `PENDING`, the waiting form automatically submits and the flow proceeds. The legacy `GET /push-mfa/login/pending` endpoint is still available for scripts and debugging, but browsers no longer rely on polling.

### Enrollment SSE details

- **Endpoint:** `GET /realms/<realm>/push-mfa/enroll/challenges/{challengeId}/events?secret=<watchSecret>` streams `text/event-stream`. The `watchSecret` is a per-challenge random value stored in `PushChallenge.watchSecret`; it prevents other sessions from observing enrollment progress.
- **Server loop:** `PushMfaResource#emitEnrollmentEvents` runs asynchronously, polls the challenge store every second, and emits a `status` event whenever the challenge state changes or an error occurs. Each event payload is JSON shaped like:

  ```json
  {
    "status": "PENDING | APPROVED | DENIED | NOT_FOUND | FORBIDDEN | INVALID | INTERRUPTED",
    "challengeId": "<uuid>",
    "expiresAt": "2025-11-14T13:16:12.902Z",
    "resolvedAt": "2025-11-14T13:16:22.180Z"
  }
  ```

  Failures (missing secret, secret mismatch, challenge not found, thread interruption, serialization errors) are logged at INFO level so pod logs provide a complete timeline for troubleshooting.

- **Client behavior:** The enrollment page (`push-register.ftl`) spins up a single `EventSource` pointed at the `eventsUrl`. When a non-`PENDING` status arrives the stream is closed and the hidden `check` form is submitted, allowing Keycloak’s RequiredAction to complete without any manual refresh. If the connection drops (pod restart, network flap) the browser’s native EventSource automatically retries; the script only logs `error` events for visibility.

- **No polling fallback:** Unlike earlier iterations the SSE client never schedules timer-based polling. If EventSource is missing (very old browsers) the script simply logs a warning, which is acceptable in this demo because enrollment is expected to run in modern browsers.

### Login SSE details

- **Endpoint:** `GET /realms/<realm>/push-mfa/login/challenges/{cid}/events?secret=<watchSecret>` streams the status for a login challenge. The authenticator generates a fresh `watchSecret` for every login, stores it with the challenge, and exposes the fully qualified SSE URL to the `push-wait.ftl` template via `pushChallengeWatchUrl`.

- **Server loop:** `PushMfaResource#emitLoginChallengeEvents` mirrors the enrollment loop and emits JSON payloads such as:

  ```json
  {
    "status": "PENDING | APPROVED | DENIED | EXPIRED | NOT_FOUND | FORBIDDEN | BAD_TYPE | INVALID | INTERRUPTED",
    "challengeId": "8fb0bc35-3e9f-4a9e-b9c1-5bb0bd963044",
    "expiresAt": "2025-11-17T10:24:11.446Z",
    "resolvedAt": "2025-11-17T10:24:35.100Z",
    "clientId": "account-console"
  }
  ```

- **Client behavior:** The waiting login form starts an `EventSource` and listens for `status` events. As soon as the status changes away from `PENDING`, the stream is closed and the (already prepared) form posts back to Keycloak, resuming the authentication flow without additional HTTP polling. If SSE is unavailable or the connection fails repeatedly, the script falls back to a single delayed form submission so the classic polling logic still works as a safety net.

## Validation Checks by Step

- **Enrollment token / QR:** Keycloak signs the `enrollmentToken` with the realm key and encodes `sub`, `enrollmentId`, `nonce`, and `exp` in the QR. The app should verify the signature against `/realms/demo/protocol/openid-connect/certs` plus issuer/audience/expiry before using it.
- **Complete enrollment (`POST /realms/demo/push-mfa/enroll/complete`):** The server ensures the challenge exists, belongs to the user, and is still `PENDING`, checks `exp` and nonce, requires a supported algorithm embedded in `cnf.jwk` (no extra `algorithm` field), enforces header/`cnf` algorithm compatibility, and verifies the JWT signature with the posted JWK before persisting the credential id and optional `deviceId`.
- **Confirm token + SSE:** Each login creates a fresh challenge and confirm token signed by the realm key containing only the credential id and `cid` (plus `typ`/`ver` and `exp`). The confirm token intentionally omits `client_id`/`client_name`, so the mobile app must call `/push-mfa/login/pending` after receiving a push to fetch the username and client metadata and surface that information to the user before asking for approval. SSE watchers for enrollment/login require the per-challenge `watchSecret` and abort on missing/mismatched secrets or the wrong challenge type before streaming status.
- **DPoP-protected API calls (`/login/pending`, `/login/challenges/{cid}/respond`, `/device/*`):** Keycloak re-verifies the access token, confirms the `cnf.jkt` thumbprint matches the stored JWK, checks the DPoP proof `htm`/`htu`, ensures `iat` is within ±120 seconds, and requires `sub` + `deviceId` to match a stored credential (enforcing the algorithm declared in the JWK) before accepting the request-level DPoP signature.
- **Login approval JWT (`POST /realms/demo/push-mfa/login/challenges/{cid}/respond` body):** After DPoP auth, the login token must match the challenge id, pass signature/`exp` checks against the stored key, carry the correct `credId`, use an algorithm compatible with the stored JWK, and declare `action` as `approve` or `deny`. If the challenge is bound to a specific credential id, mismatched devices are rejected.

## DPoP Authentication

All push REST endpoints (except enrollment) rely on [OAuth 2.0 Demonstration of Proof-of-Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449) to prove that requests come from the enrolled device:

1. **User key material** is generated during enrollment and stored as a credential on the user. Keep the private key on the device; Keycloak stores the public JWK (and an optional `deviceId` if you let a user enroll more than one device).
2. **Access tokens** are obtained using the device client credentials (`push-device-client`) and an attached DPoP proof. The access token’s `cnf.jkt` claim is bound to the user key’s thumbprint.
3. **API calls** supply both `Authorization: DPoP <access_token>` and a fresh `DPoP` header that contains the HTTP method (`htm`), URI (`htu`), timestamp (`iat`), nonce (`jti`), and the same `sub`/`deviceId` used at enrollment.
4. **Server verification** re-checks the access token signature (using the realm key), ensures the `cnf.jkt` matches the stored JWK, validates the DPoP proof (signature with the user key, method/URL, `sub`/`deviceId`, freshness), and rejects the request if any of those steps fail. The device never sees the realm’s signing key, and Keycloak never sees the private user key.

### DPoP Proof Structure

The proof is a signed JWT:

The header embeds the device’s public JWK and the proof is signed with the corresponding private key:

```json
{
  "alg": "RS256",
  "typ": "dpop+jwt",
  "jwk": {
    "kty": "RSA",
    "n": "…base64…",
    "e": "AQAB",
    "kid": "user-key-31c3"
  }
}
```

Payload:

```json
{
  "htm": "POST",
  "htu": "https://example.com/realms/demo/push-mfa/login/pending?userId=87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
  "iat": 1731402960,
  "jti": "6c1f8a0c-4c6e-4d67-b792-20fd3eb1adfc",
  "sub": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
  "deviceId": "device-3d7a4e65-9bd6-4df3-9c7d-2b3e0ce9e1a5"
}
```

The server rejects proofs if `htm`/`htu` don’t match the actual request, if the `sub` user doesn’t own the `deviceId`, or if the proof’s signature doesn’t verify with the stored JWK.

### Obtaining a DPoP-Bound Access Token

The device creates a proof for the token endpoint (`POST /protocol/openid-connect/token`), signs it with the user key, and includes it via the `DPoP` header while using the device client credentials. Pseudocode:

```bash
REALM_BASE=http://localhost:8080/realms/demo
TOKEN_ENDPOINT="$REALM_BASE/protocol/openid-connect/token"
CLIENT_ID=push-device-client
CLIENT_SECRET=device-client-secret
USER_KEY=./user-private-key.pem
USER_JWK='{"kty":"RSA","n":"...","e":"AQAB","kid":"user-key-31c3"}'

# Create JSON header/payload, base64url-encode, and sign with USER_KEY.
DPoP_PROOF=$(echo -n "<header>.<payload>" | openssl dgst -binary -sha256 -sign "$USER_KEY" | base64urlencode)

curl -s -X POST "$TOKEN_ENDPOINT" \
  -H "DPoP: $DPoP_PROOF" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET"
```

The response’s `access_token` is then sent with `Authorization: DPoP <access_token>` on every subsequent API call along with a new DPoP header tailored to the specific endpoint. The token is a standard Keycloak JWT:

Header:

```json
{ "alg": "RS256", "typ": "JWT", "kid": "realm-key-id" }
```

Payload:

```json
{
  "iss": "http://localhost:8080/realms/demo",
  "sub": "service-account-push-device-client",
  "aud": "account",
  "exp": 1763381192,
  "iat": 1763380892,
  "azp": "push-device-client",
  "scope": "email profile",
  "cnf": {
    "jkt": "s3E3x7ARe2vVffo1QOxzWIOh3aDzLzLG4zGz7d5vknU"
  }
}
```

## Custom Keycloak APIs

All endpoints live under `/realms/demo/push-mfa`. Enrollment completion posts the device JWT in the request body, while every other endpoint requires a DPoP header signed with the user key (the structure shown above). Access tokens still come from the device client credentials, but they are DPoP-bound so every request is cryptographically tied to the hardware key material.

### Complete enrollment

```
POST /realms/demo/push-mfa/enroll/complete
Content-Type: application/json

{
  "token": "<device-signed enrollment JWT>"
}
```

Keycloak verifies the signature using `cnf.jwk`, persists the credential (JWK, deviceType, `pushProviderId`, `pushProviderType`, credentialId, deviceId, deviceLabel), and resolves the enrollment challenge. The `pushProviderId` value is whatever identifier your push backend requires (for example an FCM registration token or an APNs device token), while `pushProviderType` selects the Keycloak `PushNotificationSender` provider that should deliver the confirm token. The bundled logging implementation exposes the type `log`, which simply prints the payload. Your scripts use `pushProviderType=log` by default, but real deployments can plug in any provider via the [Push Notification SPI](#push-notification-spi). The `deviceLabel` is read from the JWT payload (falls back to `PushMfaConstants.USER_CREDENTIAL_DISPLAY_NAME` when absent).

```json
{
  "status": "enrolled"
}
```

### List pending login challenges

```
GET /realms/demo/push-mfa/login/pending?userId=<keycloak-user-id>
Authorization: DPoP <access-token>
DPoP: <proof JWT>
```

The `DPoP` header carries a short-lived JWT signed with the user key (see the example above). Its payload must include `htm`, `htu`, `iat`, `jti`, plus the custom `sub` (Keycloak user id) and `deviceId`. Keycloak verifies the signature using the stored credential and only returns pending challenges tied to that device id.

```json
  {
    "challenges": [
      {
        "userId": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
        "username": "test",
        "cid": "1a6d6a0b-3385-4772-8eb8-0d2f4dbd25a4",
        "expiresAt": 1731402972,
        "clientId": "test-app",
        "clientName": "Test App"
      }
  ]
}
```

If the credential referenced by the device assertion does not own an outstanding challenge, the array is empty even if other devices for the same user are awaiting approval.

If the authenticator is configured with `userVerification`, each entry also includes a `userVerification` object:

- `{"type":"number-match","numbers":["5","34","56"]}` – show the three options and let the user tap the number shown in the browser (values are strings in the range `0`–`99` without leading zeros).
- `{"type":"pin","pinLength":<n>}` – ask the user to enter the PIN shown in the browser (`pinLength` matches `userVerificationPinLength`). The PIN may start with `0`, so send it as a string and preserve leading zeros in `userVerification`.

`expiresAt` is expressed in Unix seconds (the same format used by JWT `exp` claims) so the device can reuse its existing JWT helpers for deadline calculations.

### Approve or deny a challenge

```
POST /realms/demo/push-mfa/login/challenges/{cid}/respond
Authorization: DPoP <access-token>
DPoP: <proof JWT>
Content-Type: application/json

{
  "token": "<device-signed login JWT>"
}
```

Keycloak verifies the DPoP proof to authenticate the device, then validates the login token (stored in the request body) with the saved JWK. The login token must carry `cid`, `credId`, `deviceId`, and `action`. `"action": "approve"` marks the challenge as approved; `"action": "deny"` marks it as denied. Any other value is rejected. When `userVerification` is enabled, `"action": "approve"` also requires `userVerification` (selected number / entered PIN); `"deny"` never does.

```json
{ "status": "approved" }
```

If `userVerification` is enabled, Keycloak returns an error when the device omits or provides a wrong value (`400`/`403`):

Missing (`400`):

```json
{ "error": "Missing user verification" }
```

Mismatch (`403`):

```json
{ "error": "User verification mismatch" }
```

### Update the push provider

```
PUT /realms/demo/push-mfa/device/push-provider
Authorization: DPoP <access-token>
DPoP: <proof JWT>
Content-Type: application/json

{
  "pushProviderId": "new-provider-token",
  "pushProviderType": "log"
}
```

Keycloak authenticates the request with the current user key and replaces the stored push provider identifier and/or type tied to that credential. The response body is `{ "status": "updated" }` (or `"unchanged"` if the values were already in sync). Use this endpoint whenever your downstream push provider rotates registration tokens (e.g., new FCM registration token, APNs device token refresh, proprietary push subscription id, etc.), or when you want to switch to a different `PushNotificationSender` implementation. Omitting `pushProviderType` keeps the existing type.

> Demo helper: `scripts/update-push-provider.sh <credential-id> <provider-id> [provider-type]`

### Rotate the user key

```
PUT /realms/demo/push-mfa/device/rotate-key
Authorization: DPoP <access-token>
DPoP: <proof JWT>
Content-Type: application/json

{
  "publicKeyJwk": {
    "kty": "RSA",
    "n": "....",
    "e": "AQAB",
    "alg": "RS256",
    "use": "sig",
    "kid": "user-key-rotated"
  }
}
```

The DPoP proof must be signed with the *existing* user key. After validation, Keycloak swaps the stored JWK (and updates the credential timestamp). The response is `{ "status": "rotated" }`. Future API calls must be signed with the newly-installed key.

> Demo helper: `scripts/rotate-user-key.sh <credential-id>`

### Demo CLI scripts

The repository includes thin shell wrappers that simulate a device:

- `scripts/enroll.sh <enrollment-token>` decodes the QR payload, generates a key pair (RSA or EC), and completes enrollment.
- `scripts/confirm-login.sh <confirm-token>` decodes the Firebase-style payload, lists pending challenges (for demo visibility), and approves/denies the challenge (set `LOGIN_USER_VERIFICATION` or use the prompt when `userVerification` is enabled).
- `scripts/update-push-provider.sh <credential-id> <provider-id> [provider-type]` updates the stored push provider metadata (defaults to the `log` provider used in this demo).
- `scripts/rotate-user-key.sh <credential-id>` rotates the user key material and immediately persists the new JWK.

All scripts source `scripts/common.sh`, which centralizes base64 helpers, compact-JWS signing, DPoP proof creation, and token acquisition. The helper expects `scripts/sign_jws.py` to exist (or `COMMON_SIGN_JWS` to point to a compatible signer), so replacing the demo logic with a real implementation only requires swapping in a different signer.

## Configuration Reference

This section provides a comprehensive reference for all configuration options. For step-by-step setup instructions, see the [Setup Guide](#setup-guide) above.

### Where to Configure

| Configuration Type | Where to Set |
|-------------------|--------------|
| **Authenticator options** | Admin Console: **Authentication → Flows → [your flow] → ⚙️ Config** |
| **Required Action options** | Admin Console: **Authentication → Required Actions → Configure** |
| **Server-side limits** | Java system properties or environment variables (requires restart) |

### Authenticator Options (`push-mfa-authenticator`)

Configure these in the authentication flow execution settings.

| Option | Default | Description |
|--------|---------|-------------|
| `loginChallengeTtlSeconds` | `120` | How long the push notification / QR code is valid (in seconds) |
| `maxPendingChallenges` | `1` | Maximum concurrent login attempts per user. Set to `1` to prevent parallel logins |
| `userVerification` | `none` | Extra verification step (see below) |
| `userVerificationPinLength` | `4` | PIN length when using `pin` verification (max: 12) |
| `sameDeviceIncludeUserVerification` | `false` | Include verification answer in same-device deep links |
| `loginAppUniversalLink` | `my-secure://confirm` | Deep link scheme for same-device login |
| `waitChallengeEnabled` | `false` | Enable exponential backoff rate limiting (see [Wait Challenge Rate Limiting](#wait-challenge-rate-limiting)) |
| `waitChallengeBaseSeconds` | `10` | Initial wait time after first unapproved challenge |
| `waitChallengeMaxSeconds` | `3600` | Maximum wait time cap (1 hour) |
| `waitChallengeResetHours` | `24` | Hours until automatic reset of wait counter |

**User Verification Modes:**

| Mode | Browser Shows | Mobile App Must |
|------|--------------|-----------------|
| `none` | Nothing extra | Just tap approve/deny |
| `number-match` | A number (0–99) | Select the matching number from 3 options |
| `pin` | A PIN code | Enter the PIN shown in browser |

### Required Action Options (`push-mfa-register`)

Configure these in the Required Actions settings.

| Option | Default | Description |
|--------|---------|-------------|
| `enrollmentChallengeTtlSeconds` | `120` | How long the enrollment QR code is valid (in seconds) |
| `enrollmentAppUniversalLink` | `my-secure://enroll` | Deep link scheme for same-device enrollment |

### Server-Side Hardening Options

These protect the device-facing endpoints against abuse. Configure via Java system properties (recommended) or environment variables. **Requires Keycloak restart.**

**Example (Docker/container):**
```bash
JAVA_OPTS_APPEND="-Dkeycloak.push-mfa.input.maxJwtLength=8192 -Dkeycloak.push-mfa.sse.maxConnections=32"
```

#### DPoP Replay Protection

| Property | Default | Range | Description |
|----------|---------|-------|-------------|
| `keycloak.push-mfa.dpop.jtiTtlSeconds` | `300` | 30–3600 | How long used `jti` values are remembered |
| `keycloak.push-mfa.dpop.jtiMaxLength` | `128` | 16–512 | Maximum `jti` string length |

#### Input Size Limits

| Property | Default | Range | Description |
|----------|---------|-------|-------------|
| `keycloak.push-mfa.input.maxJwtLength` | `16384` | 2048–131072 | Max JWT length (access tokens, proofs, etc.) |
| `keycloak.push-mfa.input.maxJwkJsonLength` | `8192` | 512–65536 | Max JWK JSON length |
| `keycloak.push-mfa.input.maxUserIdLength` | `128` | 32–512 | Max user ID length |
| `keycloak.push-mfa.input.maxDeviceIdLength` | `128` | 32–512 | Max device ID length |
| `keycloak.push-mfa.input.maxDeviceTypeLength` | `64` | 16–256 | Max device type length |
| `keycloak.push-mfa.input.maxDeviceLabelLength` | `128` | 32–1024 | Max device label length |
| `keycloak.push-mfa.input.maxCredentialIdLength` | `128` | 32–512 | Max credential ID length |
| `keycloak.push-mfa.input.maxPushProviderIdLength` | `2048` | 64–8192 | Max push provider ID (FCM token, etc.) |
| `keycloak.push-mfa.input.maxPushProviderTypeLength` | `64` | 16–256 | Max push provider type name |

#### SSE Connection Limits

| Property | Default | Range | Description |
|----------|---------|-------|-------------|
| `keycloak.push-mfa.sse.maxConnections` | `256` | 1–1024 | Max concurrent SSE connections per pod |
| `keycloak.push-mfa.sse.maxSecretLength` | `128` | 16–1024 | Max SSE secret query parameter length |

> **Sizing tip for `maxConnections`:** Use `logins_per_second × average_approval_seconds` plus headroom. Example: 10 logins/s × 15s approval = ~150–250 connections.

## App Implementation Notes

- **Realm verification:** Enrollment starts when the app scans the QR code and reads `enrollmentToken`. Verify the JWT with the realm JWKS (`/realms/demo/protocol/openid-connect/certs`) before trusting its contents.
- **User key material:** Generate a key pair per user (or per device if you let a user enroll more than one), select a unique `kid`, and keep the private key in secure storage. Persist and exchange the public component exclusively as a JWK (the same document posted in `cnf.jwk`). With a single device per user you can reuse a stable `deviceId`; only multi-device setups need distinct ids.
- **Algorithm choice:** The demo scripts default to RSA/RS256 but also support EC keys and ECDSA proofs—set `DEVICE_KEY_TYPE=EC`, pick a curve via `DEVICE_EC_CURVE` (P-256/384/521), and override `DEVICE_SIGNING_ALG` if you need ES256/384/512. The selected algorithm lives in the stored JWK (no extra `algorithm` property is stored or sent) so Keycloak enforces it for all future DPoP proofs, login approvals, and rotation requests.
- **State to store locally:** credential id ↔ real Keycloak user id mapping, the user key pair, the `kid`, `deviceType`, `pushProviderId`, `pushProviderType`, preferred `deviceLabel`, and any metadata needed to post to Keycloak again. Track a `deviceId` only when you support multiple devices per user.
- **Confirm token handling:** When the confirm token arrives through Firebase (or when the user copies it from the waiting UI), decode the JWT, extract `cid` and `credId`, then call `/push-mfa/login/pending` to load user-facing metadata (username + client id/name) before prompting the user. If the response contains `userVerification`, implement the requested UX (number match / PIN) and include `userVerification` in the signed approval JWT.
- **Pending challenge discovery:** Before calling `/push-mfa/login/pending`, build a DPoP proof that includes the HTTP method (`htm`), full URL (`htu`), `sub`, `deviceId`, `iat`, and a fresh `jti`, and send it via the `DPoP` header so Keycloak can scope the response to that physical device. The response lists each pending challenge with `clientId`, `clientName`, and `username` (plus optional `userVerification` instructions) that should be shown to the user alongside the approve/deny UI.
- **Access tokens:** Obtain a short-lived access token via the realm’s token endpoint using the device client credentials. The token request itself must include a DPoP proof, and each subsequent REST call must send `Authorization: DPoP <access-token>` alongside a fresh `DPoP` header signed with the same key.
- **Request authentication:** Every REST call (aside from enrollment, which already embeds the user key) must include a DPoP proof signed with the current user key. The proof binds the request method and URL to the hardware-backed key, making replay or reverse-engineering of a shared client secret ineffective.
- **Error handling:** Enrollment and login requests return structured error responses (`400`, `403`, or `404`) when the JWTs are invalid, expired, or mismatched. Surface those errors to the user to re-trigger the flow if necessary.
- **Key rotation / push provider changes:** Use the `/device/push-provider` and `/device/rotate-key` endpoints (described above) to update the stored metadata while authenticating with the current user key. Rotation should generate a fresh key pair, send the new public JWK (with the desired `alg`), and immediately start using the new key for every subsequent JWT.

## Push Notification SPI

The server emits confirm tokens through the `PushNotificationSender` SPI. Each device credential stores a `pushProviderId` (opaque token/identifier for your push backend) and a `pushProviderType` (the Keycloak SPI provider id). At runtime `PushNotificationService` resolves the SPI implementation by calling `session.getProvider(PushNotificationSender.class, pushProviderType)` and passes in the `pushProviderId`. The bundled `log` provider simply prints the payload, but you can plug in a real APNs/FCM sender by implementing:

```java
public final class MyPushSender implements PushNotificationSender {
    @Override
    public void send(KeycloakSession session,
                     RealmModel realm,
                     UserModel user,
                     String confirmToken,
                     String credentialId,
                     String challengeId,
                     String pushProviderId,
                     String clientId) {
        // Serialize confirmToken into the mobile push message and deliver it via FCM/APNs/etc.
    }
}
```

Create a matching factory:

```java
public final class MyPushSenderFactory implements PushNotificationSenderFactory {
    @Override
    public PushNotificationSender create(KeycloakSession session) {
        return new MyPushSender();
    }
    @Override public String getId() { return "fcm"; }
    // init/postInit/close can remain empty
}
```

Register the factory via the standard service loader file for the SPI you are extending:

```
META-INF/services/de.arbeitsagentur.keycloak.push.spi.PushNotificationSenderFactory
```

Finally, you must store your factory id (for example, `pushProviderType=fcm`) with each credential during enrollment. The runtime resolves the sender solely from that `pushProviderType`, falling back to the built-in `log` sender if it is blank. Demo scripts keep sending `pushProviderType=log`, so they continue using the logging behavior unless you change their configuration.

With these primitives an actual mobile app UI or automation can be layered on top without depending on helper shell scripts.

## Push MFA Event SPI

The extension provides an event SPI that allows you to react to push MFA lifecycle events. This is useful for audit logging, metrics collection, security monitoring, or triggering external workflows.

### Available Events

| Event | When Fired | Key Data |
|-------|------------|----------|
| `ChallengeCreatedEvent` | New authentication or enrollment challenge issued | `challengeId`, `challengeType`, `userId`, `clientId`, `userVerificationMode` |
| `ChallengeAcceptedEvent` | User approved the challenge on their device | `challengeId`, `challengeType`, `userId`, `deviceId` |
| `ChallengeDeniedEvent` | User denied the challenge on their device | `challengeId`, `challengeType`, `userId`, `deviceId` |
| `ChallengeResponseInvalidEvent` | Response validation failed (bad signature, wrong PIN, etc.) | `challengeId`, `userId`, `reason` |
| `EnrollmentCompletedEvent` | Device enrollment finished successfully | `challengeId`, `userId`, `credentialId`, `deviceId`, `deviceType` |
| `KeyRotatedEvent` | Device key was successfully rotated | `userId`, `credentialId`, `deviceId` |
| `KeyRotationDeniedEvent` | Key rotation request failed validation | `userId`, `credentialId`, `reason` |
| `DpopAuthenticationFailedEvent` | DPoP authentication failed for device API request | `userId`, `credentialId`, `reason`, `httpMethod`, `requestPath` |

All events include `realmId`, `userId` (may be null for early auth failures), and `timestamp`.

### Built-in Listeners

The extension ships with two default listeners that are active out of the box:

#### Keycloak Event Bridge (`keycloak-event-bridge`)

This listener bridges Push MFA events to Keycloak's standard event system, making them visible in:

- **Keycloak Admin Console** (Events tab)
- **Keycloak Event Store** (database, queryable via Admin API)
- **Standard Keycloak EventListenerProviders** (for SIEM integration, webhooks, etc.)

Event type mappings to Keycloak events:

| Push MFA Event | Keycloak EventType | Error Code |
|----------------|-------------------|------------|
| `ChallengeCreatedEvent` | `CUSTOM_REQUIRED_ACTION` | - |
| `ChallengeAcceptedEvent` | `LOGIN` | - |
| `ChallengeDeniedEvent` | `LOGIN_ERROR` | `push_mfa_challenge_denied` |
| `ChallengeResponseInvalidEvent` | `LOGIN_ERROR` | `push_mfa_invalid_response` |
| `EnrollmentCompletedEvent` | `CUSTOM_REQUIRED_ACTION` | - |
| `KeyRotatedEvent` | `UPDATE_CREDENTIAL` | - |
| `KeyRotationDeniedEvent` | `UPDATE_CREDENTIAL_ERROR` | `push_mfa_key_rotation_denied` |
| `DpopAuthenticationFailedEvent` | `LOGIN_ERROR` | `push_mfa_dpop_auth_failed` |

All bridged events include a `push_mfa_event_type` detail with the original event type name, plus event-specific details prefixed with `push_mfa_` (e.g., `push_mfa_challenge_id`, `push_mfa_device_id`).

#### Logging Listener (`log`)

Logs all events at INFO level with DEBUG details. Configure Keycloak's logging to see the output:

```properties
quarkus.log.category."de.arbeitsagentur.keycloak.push.spi.event".level=DEBUG
```

### Multiple Active Listeners

The Push MFA Event SPI supports multiple active listeners simultaneously. All registered listeners receive every event, wrapped in exception handling to prevent one failing listener from affecting others. This means you can:

- Use the built-in Keycloak bridge for Admin Console visibility
- Use the logging listener for debugging
- Add your own custom listeners for metrics, webhooks, or external integrations

All listeners are discovered via the standard Java ServiceLoader mechanism.

### Implementing a Custom Event Listener

Create a listener that implements `PushMfaEventListener`:

```java
public class MyEventListener implements PushMfaEventListener {

    @Override
    public void onEvent(PushMfaEvent event) {
        // Called for ALL events - useful for generic logging/metrics
        System.out.println("Event: " + event.eventType() + " user=" + event.userId());
    }

    @Override
    public void onChallengeAccepted(ChallengeAcceptedEvent event) {
        // Called specifically for accepted challenges
        auditLog.info("User {} approved login from device {}",
            event.userId(), event.deviceId());
    }

    @Override
    public void onChallengeResponseInvalid(ChallengeResponseInvalidEvent event) {
        // Security alert: potential attack
        securityMonitor.alert("Invalid response for user {}: {}",
            event.userId(), event.reason());
    }

    // Override only the events you care about - all methods have default empty implementations
}
```

Create a matching factory:

```java
public class MyEventListenerFactory implements PushMfaEventListenerFactory {

    @Override
    public PushMfaEventListener create(KeycloakSession session) {
        return new MyEventListener();
    }

    @Override
    public String getId() {
        return "my-event-listener";
    }

    // init/postInit/close can remain empty
}
```

Register the factory via the service loader file:

```
META-INF/services/de.arbeitsagentur.keycloak.push.spi.event.PushMfaEventListenerFactory
```

Your custom listener will run alongside the built-in listeners (Keycloak event bridge and logging).

### Thread Safety

- Events are fired synchronously on the request thread
- Each listener is wrapped in exception handling to prevent one failing listener from affecting others
- Event objects are immutable Java records, safe to pass between threads
- For heavy processing (webhooks, external APIs), implement async handling in your listener

## Wait Challenge Rate Limiting

The extension includes an optional rate limiting feature that prevents abuse by requiring users to wait between authentication attempts when they don't approve their push challenges. This uses exponential backoff: the wait time doubles with each consecutive unapproved challenge.

### How It Works

1. **First unapproved challenge**: User must wait the base time (default 10s) before requesting another
2. **Second unapproved**: Wait time doubles (20s)
3. **Third unapproved**: Wait time doubles again (40s)
4. **And so on...** until reaching the configured maximum (default 1 hour)

The wait counter resets when:
- The user **approves** a challenge successfully
- The configured reset period elapses (default 24 hours since the first unapproved challenge)

### Enabling Wait Challenge Rate Limiting

Configure the authenticator in the Admin Console under **Authentication → Flows → [your flow] → ⚙️ Config**:

| Option | Default | Description |
|--------|---------|-------------|
| `waitChallengeEnabled` | `false` | Enable/disable the feature |
| `waitChallengeBaseSeconds` | `10` | Initial wait time in seconds |
| `waitChallengeMaxSeconds` | `3600` | Maximum wait time cap (1 hour) |
| `waitChallengeResetHours` | `24` | Hours until automatic reset |

### Wait Time Progression

With default settings (base=10s, max=3600s):

| Consecutive Unapproved | Wait Time |
|------------------------|-----------|
| 1 | 10 seconds |
| 2 | 20 seconds |
| 3 | 40 seconds |
| 4 | 80 seconds |
| 5 | 160 seconds (~2.5 min) |
| 6 | 320 seconds (~5 min) |
| 7 | 640 seconds (~10 min) |
| 8 | 1280 seconds (~21 min) |
| 9+ | 3600 seconds (capped at 1 hour) |

### Storage Provider SPI

The wait challenge state storage is pluggable via Keycloak's SPI mechanism (`push-mfa-wait-challenge-state`). The extension ships with two implementations:

#### `default` (SingleUseObject - Default)

Uses Keycloak's `SingleUseObjectProvider` for in-memory storage with automatic TTL-based expiry. This provider is automatically selected when no explicit configuration is set.

| Aspect | Behavior |
|--------|----------|
| **Provider ID** | `default` |
| **Performance** | Fast (in-memory) |
| **Survives restart** | No (state lost on pod restart) |
| **Cleanup** | Automatic via TTL |
| **Best for** | Lower traffic, simpler setups, short reset periods |

#### `user-attribute`

Stores wait state as a JSON user attribute in the database.

| Aspect | Behavior |
|--------|----------|
| **Provider ID** | `user-attribute` |
| **Performance** | Database write per update |
| **Survives restart** | Yes (persisted in DB) |
| **Cleanup** | On-demand (deleted when expired state is read) |
| **Best for** | High traffic, must survive restarts, auditability |

#### Using User Attribute Storage

To use the persistent `user-attribute` storage instead of the default in-memory storage, configure it in `keycloak.conf`:

```properties
spi-push-mfa-wait-challenge-state-provider=user-attribute
```

Or via environment variable:

```bash
KC_SPI_PUSH_MFA_WAIT_CHALLENGE_STATE_PROVIDER=user-attribute
```

#### Implementing a Custom Provider

You can implement your own storage backend by:

1. Implementing `WaitChallengeStateProvider` interface
2. Implementing `WaitChallengeStateProviderFactory` interface with a unique provider ID
3. Registering your factory via ServiceLoader in `META-INF/services/de.arbeitsagentur.keycloak.push.spi.waitchallenge.WaitChallengeStateProviderFactory`

### Interaction with Max Pending Challenges

When wait challenge rate limiting is enabled, the `maxPendingChallenges` setting is automatically forced to `1`. This prevents users from opening multiple browser tabs to bypass the rate limit.

### User Experience

When rate limited, users see a waiting page with:
- A countdown timer showing remaining wait time
- A disabled "Retry" button that enables when the wait expires
- A message explaining why they need to wait

The template is `push-wait-required.ftl` and can be customized like other theme resources.

## Customizing the Keycloak UI

The provider ships with a lightweight theme fragment under `src/main/resources/theme-resources/`. When the extension is built, those assets are copied into the deployed theme so you can either customize them in-place or copy them into your own Keycloak theme module and override the templates via standard theme selection. The bundle contains:

- **Enrollment (Required Action)** – `templates/push-register.ftl` renders the QR code, enrollment token, and SSE watcher while the user finishes onboarding. The markup is fully self-contained: everything is driven by `data-push-*` attributes on the root element plus localized strings from `messages/messages_en.properties`. To restyle the screen, replace the HTML/CSS and keep emitting the same attributes (or call `KeycloakPushMfa.initRegisterPage(...)` manually) so the QR code and SSE wiring continue to function.
- **Login waiting UI** – `templates/push-wait.ftl` powers the “waiting for approval” screen. It subscribes to the challenge SSE endpoint via the same data attributes and optionally shows the confirm token for demo purposes. The “Open App” button uses the same-device link token (optionally carrying `userVerification` when `sameDeviceIncludeUserVerification=true`). Swap the layout or remove the token preview altogether; just ensure the `data-push-*` attributes remain if you still rely on `KeycloakPushMfa.initLoginPage(...)`.
- **Terminal pages** – `templates/push-denied.ftl` and `templates/push-expired.ftl` explain why a login stopped (canceled, denied, expired). These files only display localized strings, so they are easy to rebrand or translate by editing the template and updating the corresponding entries in `messages/messages_<locale>.properties`.

All shared browser behavior (SSE handling, QR rendering, clipboard helpers) lives in `resources/js/push-mfa.js`. The script exposes `KeycloakPushMfa.initRegisterPage`, `KeycloakPushMfa.initLoginPage`, and `KeycloakPushMfa.autoInit`, so if you move to a different frontend stack you can reuse those helpers or replace them entirely with your own EventSource/QR logic. Because every UI asset is a regular Keycloak theme resource, you customize them the same way as any other login theme: copy the template/JS/message files into your custom theme folder, adjust them, and point the realm to that theme via the admin console or `keycloak.conf`.

## Security Guarantees and Mobile Obligations

### Security guarantees provided by the extension

- **Signed artifacts end-to-end:** Enrollment and confirm tokens are JWTs signed by realm keys, and device responses are signed with the user key pair. Every hop is authenticated and tamper-evident.
- **Challenge binding:** Enrollment tokens embed a nonce plus enrollment id, and login approvals reference the opaque challenge id (`cid`), so replaying a response for a different user or challenge fails.
- **Limited data exposure:** Confirm tokens carry only the credential id and challenge id, preventing the push channel from learning the user’s identity or whether a login succeeded; the app fetches username/client metadata via `/login/pending` before showing the approval UI.
- **Short-lived state:** Challenge lifetime equals every token’s `exp`, so an attacker has at most ~2 minutes to replay data even if transport is intercepted.
- **Key continuity:** The stored `cnf.jwk` couples future approvals to the same hardware-backed key, giving Keycloak a stable signal that a response truly came from the enrolled device.
- **Hardware-bound authentication:** Every REST call is authenticated with a JWT signed by that device’s private key, which is far more secure than distributing an easily reverse-engineered client secret inside the mobile app. Stealing the client binary is no longer enough; the attacker must compromise the device’s key material as well.
- **DPoP-bound access tokens:** Each access token carries a `cnf.jkt` thumbprint that must match the enrolled device’s JWK. The server recomputes the thumbprint from the stored credential and rejects any DPoP proof or access token that doesn’t match, so only the key pair used during enrollment can successfully invoke the APIs.

### Obligations for the mobile application

- **Verify every JWT:** Check issuer, audience, signature, and `exp` on enrollment and confirm tokens before acting. Fetch the realm JWKS over HTTPS and cache it defensively.
- **Protect the user key pair:** Generate it with high-entropy sources, store the private key in Secure Enclave/Keystore/KeyChain, and never export it. Rotate/re-enroll immediately if compromise is suspected.
- **Enforce challenge integrity:** When a confirm token arrives, compare the `cid` and `credId` against locally stored state and discard anything unexpected or expired.
- **Secure transport:** Call the Keycloak endpoints only over TLS, validate certificates (no user-controlled CA overrides), and pin if your threat model requires it.
- **Harden local state:** Keep the credential id ↔ real user mapping, push provider identifiers/types, and enrollment metadata in encrypted storage with OS-level protection.
- **Surface errors to users:** Treat 4xx responses (expired, invalid signature, nonce mismatch) as security events, notifying the user and requiring a fresh enrollment or login attempt rather than silently retrying.


# Mobile Mock for push-mfa enrollment and login

## Overview

The `mock/mobile` folder contains a mock implementation simulating the behavior of a mobile application for testing the Keycloak Push MFA Extension. This mock is particularly useful for development and integration testing without requiring a real mobile device or app. It mimics the enrollment and login confirmation flows described in the project's high-level documentation, allowing developers to verify the server-side logic (e.g., Keycloak SPIs and JAX-RS endpoints) in isolation.

This mock is built using TypeScript and Node.js, leveraging packages like Express for creating a simple HTTP server that handles push notifications, token processing, and user interactions. It does not represent a production-ready mobile app but serves as a testing utility.

### Purpose
- **Testing Login & Enrollment Flow**: Simulates scanning a QR code, generating key pairs, and completing enrollment and login via API calls.

This folder is not part of the core Keycloak provider but is included for developer convenience. It can be run locally alongside the Keycloak Docker setup.

## Setup and Usage

A working mock is available in the artifact in the mock folder.

### Prerequisites
- Node.js (compatible with @types/node 22.7.5).
- npm for package management.
- Install dependencies: Run `npm install` in the `mock/mobile` folder.

### Running the Mock
1. Build the app:
```
npm run build
```
2. Start the server:
```
npm run start
```

2. The mock server listens on a port (e.g., 3001) and exposes endpoints like:
    - `/enroll`: POST endpoint to mimic QR code scanning and enrollment completion.
    - `/confirm-login`: POST endpoint to process a Keycloak `confirmToken` and respond to the login challenge (`action=approve|deny`, plus optional `userVerification` for number-match / PIN).

### Example Integration with Keycloak Flow

#### Simulating Enrollment
- The mock can "scan" a QR code by receiving the `enrollmentToken` (a JWT from Keycloak).
- It generates a device key pair and sends a signed payload to Keycloak's `/enroll/complete` endpoint.

#### Simulating Login Approval
- Receives a mock push notification with `ConfirmToken`.
- Prompts for approval (via console or UI) and sends a signed `LoginToken` to Keycloak's `/login/challenges/{cid}/respond`.

For full flow details, refer to the project's high-level sequence diagram.

## Key Concepts in the Mock
- **Token Handling**: Uses jose for JWT signing/verification, ensuring compatibility with Keycloak's realm keys.
- **DPoP (Demonstration of Proof-of-Possession)**: Mocked in headers for secure API calls.
- **Push Simulation**: Instead of real FCM/APNs, the mock can be triggered directly via API for testing.
- **Security Notes**: This is a mock; do not use real keys or expose it in production. Placeholders are used for any sensitive info (e.g., `<MOCK_DEVICE_ID>` instead of real UUIDs).

## Troubleshooting

### Docker Environment Not Found for Integration Tests

The Integration Tests require a container runtime environment. 
If you encounter the error "Could not find a valid Docker environment", this typically occurs when:

1. Docker is not running
2. You're using a non-default Docker socket
3. The container socket is not accessible

**Docker Desktop:**
- Ensure Docker Desktop is running: `docker info`
- If you previously set `DOCKER_HOST`, unset it so Testcontainers can auto-detect:
  - `unset DOCKER_HOST`

**For Podman users:**
To run the tests with Podman, configure the Docker compatibility socket:

```shell
export DOCKER_HOST=unix://${XDG_RUNTIME_DIR}/podman/podman.sock
mvn clean verify
```

**API version mismatch:**
If you see "client version 1.32 is too old", force a newer Docker API version:

```shell
mvn -Ddocker.api.version=1.44 clean verify
```

**Rootless Docker (Linux):**

```shell
export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock
mvn clean verify
```
