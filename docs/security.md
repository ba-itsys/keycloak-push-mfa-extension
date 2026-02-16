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
