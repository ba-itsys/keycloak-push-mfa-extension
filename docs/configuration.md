# Configuration Reference

This section provides a comprehensive reference for all configuration options. For step-by-step setup instructions, see the [Setup Guide](setup.md).

## Where to Configure

| Configuration Type | Where to Set |
|-------------------|--------------|
| **Authenticator options** | Admin Console: **Authentication → Flows → [your flow] → ⚙️ Config** |
| **Required Action options** | Admin Console: **Authentication → Required Actions → Configure** |
| **Server-side limits** | Keycloak config for the `push-mfa` SPI provider (requires restart) |

## Authenticator Options (`push-mfa-authenticator`)

Configure these in the authentication flow execution settings.

| Option | Default | Description |
|--------|---------|-------------|
| `loginChallengeTtlSeconds` | `240` | How long the login challenge / push notification is valid (in seconds) |
| `maxPendingChallenges` | `1` | Maximum concurrent login attempts per user (see [Challenge Behavior](#challenge-behavior) below) |
| `userVerification` | `none` | Extra verification step (see below) |
| `userVerificationPinLength` | `4` | PIN length when using `pin` verification (max: 12) |
| `sameDeviceIncludeUserVerification` | `false` | Include verification answer in same-device deep links |
| `loginAppUniversalLink` | `my-secure://confirm` | Deep link scheme for same-device login |
| `autoAddRequiredAction` | `true` | Automatically add `push-mfa-register` when the user has no Push MFA credential |
| `waitChallengeEnabled` | `false` | Enable exponential backoff rate limiting (see [Wait Challenge Rate Limiting](spi-reference.md#wait-challenge-rate-limiting)) |
| `waitChallengeBaseSeconds` | `10` | Initial wait time after first unapproved challenge |
| `waitChallengeMaxSeconds` | `3600` | Maximum wait time cap (1 hour) |
| `waitChallengeResetHours` | `24` | Hours until automatic reset of wait counter |

### User Verification Modes

| Mode | Browser Shows | Mobile App Must |
|------|--------------|-----------------|
| `none` | Nothing extra | Just tap approve/deny |
| `number-match` | A number (0–99) | Select the matching number from 3 options |
| `pin` | A PIN code | Enter the PIN shown in browser |

### Challenge Behavior

Understanding how `maxPendingChallenges` interacts with credentials:

- **One challenge per credential**: Each registered device/credential can have at most ONE pending challenge at a time. Creating a new challenge for the same credential automatically replaces the previous one. This enables the "retry" functionality where users can request a new push notification without waiting for the old one to expire.

- **Multiple credentials**: If a user has multiple registered devices (credentials), `maxPendingChallenges` limits how many concurrent challenges can exist across all credentials. For example, with `maxPendingChallenges=2` and 3 registered devices, only 2 devices can have active challenges simultaneously.

- **Recommended setting**: Keep `maxPendingChallenges=1` (the default) for most deployments. This ensures only one active login attempt at a time per user, which simplifies the security model and user experience.

- **Wait challenge interaction**: When `waitChallengeEnabled=true`, `maxPendingChallenges` is automatically forced to `1` regardless of configuration to ensure rate limiting is effective.

## Required Action Options (`push-mfa-register`)

Configure these in the Required Actions settings.

| Option | Default | Description |
|--------|---------|-------------|
| `enrollmentChallengeTtlSeconds` | `240` | How long the enrollment QR code is valid (in seconds) |
| `enrollmentAppUniversalLink` | `my-secure://enroll` | Deep link scheme for same-device enrollment |
| `enrollmentUseRequestUri` | `false` | When enabled, the QR code and same-device link carry a short-lived `request_uri` instead of the full enrollment token |
| `enrollmentRequestUriTtlSeconds` | unset | Optional shorter lifetime for the `request_uri` handle itself. When unset, it reuses the full enrollment challenge lifetime; it is always capped at the remaining challenge lifetime |

## Server-Side Hardening Options

These protect the device-facing endpoints against abuse. Configure them through Keycloak's standard SPI configuration for the `push-mfa` provider. **Requires Keycloak restart.**

**Example (`keycloak.conf` or CLI option name):**
```bash
spi-push-mfa--default--input-max-jwt-length=8192
spi-push-mfa--default--sse-max-connections=32
spi-push-mfa--default--sse-heartbeat-interval-seconds=15
spi-push-mfa--default--sse-max-connection-lifetime-seconds=55
spi-push-mfa--default--sse-reconnect-delay-millis=3000
```

Use the same option names with the usual Keycloak configuration mechanisms such as `keycloak.conf`, CLI flags, or environment variables.

### DPoP Replay Protection

| Property | Default | Range | Description |
|----------|---------|-------|-------------|
| `spi-push-mfa--default--dpop-jti-ttl-seconds` | `300` | 30–3600 | How long used `jti` values are remembered |
| `spi-push-mfa--default--dpop-jti-max-length` | `128` | 16–512 | Maximum `jti` string length |
| `spi-push-mfa--default--dpop-iat-tolerance-seconds` | `120` | 30–600 | Allowed clock skew for DPoP proof `iat` timestamp |
| `spi-push-mfa--default--dpop-require-for-enrollment` | `true` | `true`/`false` | DPoP is required for enrollment by default. Set this to `false` only for backward compatibility |
| `spi-push-mfa--default--dpop-require-ath` | `true` | `true`/`false` | Require the DPoP `ath` claim on device API requests. This mainly improves RFC 9449 conformance; in this design, authorization still primarily comes from possession of the enrolled key plus the DPoP-bound token |

### Input Size Limits

| Property | Default | Range | Description |
|----------|---------|-------|-------------|
| `spi-push-mfa--default--input-max-jwt-length` | `16384` | 2048–131072 | Max JWT length (access tokens, proofs, etc.) |
| `spi-push-mfa--default--input-max-jwk-json-length` | `8192` | 512–65536 | Max JWK JSON length |
| `spi-push-mfa--default--input-max-user-id-length` | `128` | 32–512 | Max user ID length |
| `spi-push-mfa--default--input-max-device-id-length` | `128` | 32–512 | Max device ID length |
| `spi-push-mfa--default--input-max-device-type-length` | `64` | 16–256 | Max device type length |
| `spi-push-mfa--default--input-max-device-label-length` | `128` | 32–1024 | Max device label length |
| `spi-push-mfa--default--input-max-credential-id-length` | `128` | 32–512 | Max credential ID length |
| `spi-push-mfa--default--input-max-push-provider-id-length` | `2048` | 64–8192 | Max push provider ID (FCM token, etc.) |
| `spi-push-mfa--default--input-max-push-provider-type-length` | `64` | 16–256 | Max push provider type name |

### SSE Connection Limits

| Property | Default | Range | Description |
|----------|---------|-------|-------------|
| `spi-push-mfa--default--sse-max-connections` | `256` | 1–1024 | Max number of concurrently registered SSE clients per Keycloak node |
| `spi-push-mfa--default--sse-max-secret-length` | `128` | 16–1024 | Max SSE secret query parameter length |
| `spi-push-mfa--default--sse-heartbeat-interval-seconds` | `15` | 5–300 | Interval for SSE keepalive comments while a challenge is still `PENDING` |
| `spi-push-mfa--default--sse-max-connection-lifetime-seconds` | `55` | 15–1800 | Maximum time to keep one SSE connection open before closing it and letting `EventSource` reconnect |
| `spi-push-mfa--default--sse-reconnect-delay-millis` | `3000` | 250–30000 | `retry:` hint used for overload responses such as `TOO_MANY_CONNECTIONS`; normal `PENDING` streams do not use it |

> **Implementation note:** Each open SSE connection streams directly from the Keycloak node that accepted it and rereads challenge state from shared storage while the challenge is still pending. The server sends periodic heartbeat comments and rotates long-lived connections after the configured maximum lifetime so browsers reconnect cleanly through proxies and firewalls. Cross-node delivery still works because reconnects can land on any node that can read the same backing store.
