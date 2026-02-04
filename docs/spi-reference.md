# SPI Reference

This document covers the Service Provider Interfaces (SPIs) available for extending push MFA functionality.

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
META-INF/services/de.arbeitsagentur.keycloak.push.spi.PushMfaEventListenerFactory
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
| 9 | 2560 seconds (~42 min) |
| 10+ | 3600 seconds (capped at 1 hour) |

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
3. Registering your factory via ServiceLoader in `META-INF/services/de.arbeitsagentur.keycloak.push.spi.WaitChallengeStateProviderFactory`

### Interaction with Max Pending Challenges

When wait challenge rate limiting is enabled, the `maxPendingChallenges` setting is automatically forced to `1`. This prevents users from opening multiple browser tabs to bypass the rate limit.

### User Experience

When rate limited, users see a waiting page with:
- A countdown timer showing remaining wait time
- A disabled "Retry" button that enables when the wait expires
- A message explaining why they need to wait

The template is `push-wait-required.ftl` and can be customized like other theme resources.
