# Flow Details

This document provides detailed technical information about each phase of the enrollment and login flows.

## Credential ID Concepts

Each Push MFA credential has **two distinct IDs**:

| ID | Where | Purpose |
|----|-------|---------|
| **Device credential ID** (`deviceCredentialId`) | Set by the device during enrollment; stored in `PushCredentialData`; carried in tokens as `credId`, events as `push_mfa_credential_id`, and push notifications | The mobile app uses this to match incoming pushes to its local credential store. Appears in all external-facing protocols. |
| **Keycloak credential ID** (`keycloakCredentialId`) | UUID assigned by Keycloak when the `CredentialModel` is persisted; stored on `PushChallenge` | Used internally by the server to load the correct `CredentialModel` from storage. The app never sees this value. |

**Why challenges only store the Keycloak credential ID:** The server picks which credential to use for a challenge and records its Keycloak UUID so it can reload the `CredentialModel` later. The device credential ID is redundant on the challenge because:
- The app already knows its own device credential ID (it chose it during enrollment).
- The app receives the device credential ID via the `credId` claim in the confirm token.
- The server accesses the device credential ID through `PushCredentialData` after loading the `CredentialModel` by its Keycloak UUID.

## Enrollment Flow

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

4. **Login approval:** The device looks up the confirm token's `credId` (credential id), resolves it to the real Keycloak user id in its secure storage, and signs a JWT (`loginToken`) with the same key pair from enrollment. The payload echoes the challenge id (`cid`), the `credId`, and the desired `action` (`approve`/`deny`) so Keycloak can fully trust the intent because it is covered by the user key signature (no nonce is needed because possession of the key already proves authenticity, and `cid` is unguessable). If user verification is enabled, the device must include the selected number / entered PIN as `userVerification` (as a JSON string; preserve leading zeros) when approving (deny works without it).

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

## Enrollment SSE Details

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

- **Client behavior:** The enrollment page (`push-register.ftl`) spins up a single `EventSource` pointed at the `eventsUrl`. When a non-`PENDING` status arrives the stream is closed and the hidden `check` form is submitted, allowing Keycloak's RequiredAction to complete without any manual refresh. If the connection drops (pod restart, network flap) the browser's native EventSource automatically retries; the script only logs `error` events for visibility.

- **No polling fallback:** Unlike earlier iterations the SSE client never schedules timer-based polling. If EventSource is missing (very old browsers) the script simply logs a warning, which is acceptable in this demo because enrollment is expected to run in modern browsers.

## Login SSE Details

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
2. **Access tokens** are obtained using the device client credentials (`push-device-client`) and an attached DPoP proof. The access token's `cnf.jkt` claim is bound to the user key's thumbprint.
3. **API calls** supply both `Authorization: DPoP <access_token>` and a fresh `DPoP` header that contains the HTTP method (`htm`), URI without query/fragment (`htu`, per [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449#section-4.2)), timestamp (`iat`), nonce (`jti`), and the same `sub`/`deviceId` used at enrollment.
4. **Server verification** re-checks the access token signature (using the realm key), ensures the `cnf.jkt` matches the stored JWK, validates the DPoP proof (signature with the user key, method/URL, `sub`/`deviceId`, freshness), and rejects the request if any of those steps fail. The device never sees the realm's signing key, and Keycloak never sees the private user key.

### DPoP Proof Structure

The proof is a signed JWT:

The header embeds the device's public JWK and the proof is signed with the corresponding private key:

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
  "htm": "GET",
  "htu": "https://example.com/realms/demo/push-mfa/login/pending",
  "iat": 1731402960,
  "jti": "6c1f8a0c-4c6e-4d67-b792-20fd3eb1adfc",
  "sub": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
  "deviceId": "device-3d7a4e65-9bd6-4df3-9c7d-2b3e0ce9e1a5"
}
```

The server rejects proofs if `htm`/`htu` don't match the actual request, if the `sub` user doesn't own the `deviceId`, or if the proof's signature doesn't verify with the stored JWK.

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

The response's `access_token` is then sent with `Authorization: DPoP <access_token>` on every subsequent API call along with a new DPoP header tailored to the specific endpoint. The token is a standard Keycloak JWT:

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
