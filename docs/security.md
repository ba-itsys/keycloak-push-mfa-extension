# Security

This document covers the security model of the push MFA extension and the obligations for mobile app implementations.

## Security Guarantees Provided by the Extension

- **Signed artifacts end-to-end:** Enrollment and confirm tokens are JWTs signed by realm keys, and device responses are signed with the user key pair. Every hop is authenticated and tamper-evident.
- **Challenge binding:** Enrollment tokens embed a nonce plus enrollment id, and login approvals reference the opaque challenge id (`cid`), so replaying a response for a different user or challenge fails.
- **Limited data exposure:** Confirm tokens carry only the credential id and challenge id, preventing the push channel from learning the user's identity or whether a login succeeded; the app fetches username/client metadata via `/login/pending` before showing the approval UI.
- **Short-lived state:** Challenge lifetime equals every token's `exp`, so an attacker has at most a few minutes to replay data even if transport is intercepted.
- **Key continuity:** The stored `cnf.jwk` couples future approvals to the same hardware-backed key, giving Keycloak a stable signal that a response truly came from the enrolled device.
- **Hardware-bound authentication:** Every REST call is authenticated with a JWT signed by that device's private key, which is far more secure than distributing an easily reverse-engineered client secret inside the mobile app. Stealing the client binary is no longer enough; the attacker must compromise the device's key material as well.
- **DPoP-bound access tokens:** Each access token carries a `cnf.jkt` thumbprint that must match the enrolled device's JWK. The server recomputes the thumbprint from the stored credential and rejects any DPoP proof or access token that doesn't match, so only the key pair used during enrollment can successfully invoke the APIs.

## Brute Force Protector Compatibility

Keycloak's [brute force protector](https://www.keycloak.org/docs/latest/server_admin/#password-guess-detection) locks user accounts after a configurable number of `LOGIN_ERROR` events. Because `context.failureChallenge()` in the authentication SPI fires a `LOGIN_ERROR` event, MFA authenticators must be careful not to report non-credential errors as failures — otherwise benign scenarios (challenge timeouts, rate-limit hits, internal errors) can lock users out.

### What does NOT trigger the brute force protector

The authenticator uses `context.challenge()` (not `failureChallenge()`) for situations that are **not** credential failures:

| Scenario | Reason |
|----------|--------|
| **Challenge expired** | The user simply did not respond in time. Not a wrong credential. |
| **Internal / system error** | Server-side problem, not a user mistake. |
| **Creation lock contention** | Concurrent request race condition. |
| **Pending challenge limit exceeded** | Rate limiting, not a credential failure. |

These errors still display an appropriate error page but do **not** increment Keycloak's brute force failure counter.

### What DOES trigger the brute force protector

Only the explicit **challenge denied** flow — where the user (or their device) actively rejects the push challenge — calls `context.failureChallenge(INVALID_CREDENTIALS)` and increments the failure counter. This is intentional: repeated denials may indicate that an unauthorized party is attempting to log in and the legitimate user is rejecting the prompts.

Additionally, the following events fire `LOGIN_ERROR` via the [Keycloak Event Bridge](spi-reference.md#keycloak-event-bridge-keycloak-event-bridge) (if enabled). These are device-side REST API errors and are independent of the authenticator's brute force interaction:

| Event | Error Code |
|-------|------------|
| `ChallengeResponseInvalidEvent` | `push_mfa_invalid_response` |
| `DpopAuthenticationFailedEvent` | `push_mfa_dpop_auth_failed` |
| `UserLockedOutEvent` | `push_mfa_user_locked_out` |

### Recommendations

- **Keep the brute force protector enabled.** The authenticator is designed to be compatible with it.
- **Set a reasonable failure threshold.** Since only explicit denials count, the threshold can be lower than you might expect for a traditional MFA authenticator.
- **Use wait challenge rate limiting** as a complementary measure (see [SPI Reference — Wait Challenge Rate Limiting](spi-reference.md#wait-challenge-rate-limiting)). It throttles challenge creation with exponential backoff, independent of the brute force protector.

## Obligations for Mobile App Implementations

### Verify Every JWT

Check issuer, audience, signature, and `exp` on enrollment and confirm tokens before acting. Fetch the realm JWKS over HTTPS and cache it defensively.

### Protect the User Key Pair

Generate it with high-entropy sources, store the private key in Secure Enclave/Keystore/KeyChain, and never export it. Rotate/re-enroll immediately if compromise is suspected.

### Enforce Challenge Integrity

When a confirm token arrives, compare the `cid` and `credId` against locally stored state and discard anything unexpected or expired.

### Secure Transport

Call the Keycloak endpoints only over TLS, validate certificates (no user-controlled CA overrides), and pin if your threat model requires it.

### Harden Local State

Keep the credential id ↔ real user mapping, push provider identifiers/types, and enrollment metadata in encrypted storage with OS-level protection.

### Surface Errors to Users

Treat 4xx responses (expired, invalid signature, nonce mismatch) as security events, notifying the user and requiring a fresh enrollment or login attempt rather than silently retrying.

## SSE Watcher Security

The browser-side SSE endpoints are not DPoP-protected and are not bound to the Keycloak browser session. They are protected by a per-challenge random `watchSecret` carried in the watcher URL.

- Treat the full SSE URL, including `?secret=...`, as a bearer secret.
- Anyone who learns that URL can observe the matching challenge status until it resolves or expires.
- Observing SSE status does not let the watcher approve or deny the challenge; those actions still require the enrolled device key and DPoP-bound API calls.

### Operational Guidance

- Avoid logging full query strings for `/realms/<realm>/push-mfa/*/events`.
- Keep the login and enrollment pages free of third-party JavaScript.
- Use a restrictive Content Security Policy so injected scripts cannot read and exfiltrate the SSE URL from the DOM.
- Keep XSS protections on the Keycloak theme pages high, because XSS on those pages can steal the SSE capability URL.

## Enrollment `request_uri` Security

When `enrollmentUseRequestUri=true`, the QR code and same-device app link no longer carry the full enrollment JWT directly. Instead, they carry a short-lived `request_uri` that points to `/realms/<realm>/push-mfa/enroll/request-token/{requestHandle}`.

### Security Properties

- The `requestHandle` is a random opaque capability value generated server-side. Security depends primarily on that handle being unguessable and on the short lifetime described below.
- The endpoint is intentionally bearer-style: anyone who knows the full `request_uri` can fetch the enrollment token until the handle expires or is removed. The URL itself must therefore be treated as a secret.
- A successful fetch does **not** complete enrollment by itself, but it is enough to let another device attempt enrollment. If an attacker obtains the `request_uri` early enough, they can fetch the same enrollment JWT and try to bind their own device to that pending enrollment challenge before the intended user does.
- Compared with embedding the full JWT in the QR code, by-reference mode reduces accidental exposure in screenshots, scanner logs, browser history sync, analytics tooling, and copy/paste mistakes because the QR carries only an opaque reference, not the full signed token payload.

### User Detection and Visibility

- The enrollment flow does **not** cryptographically distinguish an "intended" device from any other device that legitimately obtains the enrollment token in time. This is true for both direct-token QR codes and `request_uri` mode.
- Detecting whether the "correct" device enrolled is not possible from the protocol alone, because the server has no prior identity for the device unless that device was provisioned out of band before enrollment starts.
- If another party completes enrollment first, the most likely user-visible effects are indirect:
  - the browser enrollment page will move to success even though the phone the user expected to use did not finish enrollment;
  - the user-expected phone may fail with "already resolved or expired" once it tries to complete;
  - later account/device views may show an unexpected enrolled device label or push target, if the user already knows what they expected to see.
- The primary protection is therefore preventing disclosure of the QR contents in the first place, not detecting the "right" device after the fact.

### Guessing Resistance

- An attacker who does **not** know the URL would have to guess a valid `requestHandle`.
- The implementation uses a random Keycloak-generated identifier and validates that it resolves to a live pending enrollment challenge in the same realm before returning a token.
- Unknown, expired, refreshed, resolved, or cross-realm-invalid handles return `404 Not Found`.
- In practice, brute-forcing a valid handle is expected to be impractical because the handle is random and the acceptance window is short. This property relies on strong randomness; it is not based on obscurity of the endpoint path.
- Because the endpoint is not otherwise authenticated, deployments that expect aggressive internet scanning should still rely on normal perimeter protections such as ingress/WAF rate limiting, TLS termination you trust, and log hygiene.

### Lifetime and Revocation

- By default the handle lifetime matches the enrollment challenge lifetime.
- By default that is `240` seconds, controlled by the required-action setting `enrollmentChallengeTtlSeconds`.
- Operators can shorten the handle lifetime independently via `enrollmentRequestUriTtlSeconds` if they want a tighter bearer-URL exposure window while keeping the overall enrollment challenge alive longer.
- If the user refreshes the enrollment page, completes enrollment, or the challenge otherwise stops being `PENDING`, the old handle stops working.
- The fetched enrollment JWT is still bounded by the same challenge expiry, so a late fetch does not extend the enrollment window.
- The handle TTL is never allowed to outlive the remaining enrollment challenge lifetime.
- The implementation keeps the handle reusable during its configured window so the same QR code can be scanned again after camera/app handoff issues, transient network failures, or user retries. A one-shot or very-short-lived handle would reduce replay exposure further, but it would also make rescans and wallet fetch retries much more brittle.
- Fetching the `request_uri` is treated as a read of pending enrollment state, not as proof that the app fetching it is definitely the final enrolling device. That is why the server does not invalidate the handle on first fetch.

### Transport and Caching Requirements

- Always fetch the `request_uri` over HTTPS and validate certificates normally.
- Do not log the full `request_uri` in reverse proxies, app telemetry, crash reports, mobile analytics, or browser console output.
- The endpoint responds with `Cache-Control: no-store` and `Pragma: no-cache`, but clients and intermediaries should still be configured conservatively because the URL is a bearer capability.

### Mobile App Guidance

- Treat the `request_uri` like a short-lived bearer secret, not a stable API endpoint.
- Fetch it immediately, discard it after use, and avoid storing it on disk.
- After fetching, continue to verify the returned enrollment JWT exactly as before: issuer, audience, signature, and `exp` must all be checked before acting on it.
