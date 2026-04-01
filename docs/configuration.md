# Configuration Reference

This section provides a comprehensive reference for all configuration options. For step-by-step setup instructions, see the [Setup Guide](setup.md).

## Where to Configure

| Configuration Type | Where to Set |
|-------------------|--------------|
| **Authenticator options** | Admin Console: **Authentication → Flows → [your flow] → ⚙️ Config** |
| **Required Action options** | Admin Console: **Authentication → Required Actions → Configure** |
| **Server-side limits** | Java system properties or environment variables (requires restart) |

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

## Server-Side Hardening Options

These protect the device-facing endpoints against abuse. Configure via Java system properties (recommended) or environment variables. **Requires Keycloak restart.**

**Example (Docker/container):**
```bash
JAVA_OPTS_APPEND="-Dkeycloak.push-mfa.input.maxJwtLength=8192 -Dkeycloak.push-mfa.sse.maxConnections=32 -Dkeycloak.push-mfa.sse.heartbeatIntervalSeconds=15 -Dkeycloak.push-mfa.sse.maxConnectionLifetimeSeconds=55 -Dkeycloak.push-mfa.sse.reconnectDelayMillis=3000"
```

### DPoP Replay Protection

| Property | Default | Range | Description |
|----------|---------|-------|-------------|
| `keycloak.push-mfa.dpop.jtiTtlSeconds` | `300` | 30–3600 | How long used `jti` values are remembered |
| `keycloak.push-mfa.dpop.jtiMaxLength` | `128` | 16–512 | Maximum `jti` string length |
| `keycloak.push-mfa.dpop.iatToleranceSeconds` | `120` | 30–600 | Allowed clock skew for DPoP proof `iat` timestamp |

### Input Size Limits

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

### SSE Connection Limits

| Property | Default | Range | Description |
|----------|---------|-------|-------------|
| `keycloak.push-mfa.sse.maxConnections` | `256` | 1–1024 | Max number of concurrently registered SSE clients per Keycloak node |
| `keycloak.push-mfa.sse.maxSecretLength` | `128` | 16–1024 | Max SSE secret query parameter length |
| `keycloak.push-mfa.sse.heartbeatIntervalSeconds` | `15` | 5–300 | Interval for SSE keepalive comments while a challenge is still `PENDING` |
| `keycloak.push-mfa.sse.maxConnectionLifetimeSeconds` | `55` | 15–1800 | Maximum time to keep one SSE connection open before closing it and letting `EventSource` reconnect |
| `keycloak.push-mfa.sse.reconnectDelayMillis` | `3000` | 250–30000 | `retry:` hint used for overload responses such as `TOO_MANY_CONNECTIONS`; normal `PENDING` streams do not use it |

> **Implementation note:** Each Keycloak node runs one node-local poller that checks shared challenge storage for all registered local SSE clients, grouped by challenge. While a challenge stays `PENDING`, the server sends periodic heartbeat comments and rotates long-lived connections after the configured maximum lifetime so browsers reconnect cleanly through proxies and firewalls. This avoids one sleeping worker thread per connection while still working across multiple Keycloak nodes, as long as every node can read the same backing store.
