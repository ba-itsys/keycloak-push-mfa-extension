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
                     String deviceCredentialId,
                     String challengeId,
                     String pushProviderId,
                     String clientId) {
        // Serialize confirmToken into the mobile push message and deliver it via FCM/APNs/etc.
        // deviceCredentialId is the device-chosen credential ID (not the Keycloak-internal UUID).
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
| `ChallengeCreatedEvent` | New authentication or enrollment challenge issued | `challengeId`, `challengeType`, `clientId`, `userVerificationMode` |
| `ChallengeAcceptedEvent` | User approved the challenge on their device | `challengeId`, `challengeType`, `clientId`, `deviceId` |
| `ChallengeDeniedEvent` | User denied the challenge on their device | `challengeId`, `challengeType`, `clientId`, `deviceId` |
| `ChallengeResponseInvalidEvent` | Response validation failed (bad signature, wrong PIN, etc.) | `challengeId`, `clientId`, `reason` |
| `EnrollmentCompletedEvent` | Device enrollment finished successfully | `challengeId`, `clientId`, `deviceCredentialId`, `deviceId`, `deviceType` |
| `KeyRotatedEvent` | Device key was successfully rotated | `clientId`, `deviceCredentialId`, `deviceId` |
| `KeyRotationDeniedEvent` | Key rotation request failed validation | `clientId`, `deviceCredentialId`, `reason` |
| `DpopAuthenticationFailedEvent` | DPoP authentication failed for device API request | `clientId`, `deviceCredentialId`, `reason`, `httpMethod`, `requestPath` |
| `UserLockedOutEvent` | Device requested user account lockout | `clientId`, `deviceCredentialId`, `deviceId` |

All events include `realmId`, `userId` (may be null for early auth failures), `clientId`, and `timestamp`. The source of `clientId` depends on the event: for `ChallengeCreatedEvent` and `EnrollmentCompletedEvent` it is the OAuth client that initiated the flow; for challenge response events (`ChallengeAcceptedEvent`, `ChallengeDeniedEvent`, `ChallengeResponseInvalidEvent`) and device API events (`KeyRotatedEvent`, `KeyRotationDeniedEvent`, `DpopAuthenticationFailedEvent`, `UserLockedOutEvent`) it is the OAuth client from the device's DPoP access token. It may be null for early DPoP auth failures or enrollment challenges without a client context.

### Built-in Listeners

The extension ships with two built-in listeners:

#### Keycloak Event Bridge (`keycloak-event-bridge`)

This listener bridges Push MFA events to Keycloak's standard event system, making them visible in:

- **Keycloak Admin Console** (Events tab)
- **Keycloak Event Store** (database, queryable via Admin API)
- **Standard Keycloak EventListenerProviders** (for SIEM integration, webhooks, etc.)

**This listener is disabled by default.** To enable it, add the following to your Keycloak configuration (`keycloak.conf` or CLI):

```properties
spi-push-mfa-event-listener--keycloak-event-bridge--enabled=true
```

Or via environment variable:

```bash
KC_SPI_PUSH_MFA_EVENT_LISTENER__KEYCLOAK_EVENT_BRIDGE__ENABLED=true
```

Event type mappings to Keycloak events:

| Push MFA Event | Keycloak EventType | Event Type Value | Error Code | Additional Detail Keys |
|----------------|-------------------|------------------|------------|------------------------|
| `ChallengeCreatedEvent` | `CUSTOM_REQUIRED_ACTION` | `CHALLENGE_CREATED` | - | `push_mfa_challenge_id`, `push_mfa_challenge_type`, `push_mfa_credential_id`, `push_mfa_user_verification` |
| `ChallengeAcceptedEvent` | `CUSTOM_REQUIRED_ACTION` | `CHALLENGE_ACCEPTED` | - | `push_mfa_challenge_id`, `push_mfa_challenge_type`, `push_mfa_credential_id`, `push_mfa_device_id` |
| `ChallengeDeniedEvent` | `LOGIN_ERROR` | `CHALLENGE_DENIED` | `push_mfa_challenge_denied` | `push_mfa_challenge_id`, `push_mfa_challenge_type`, `push_mfa_credential_id`, `push_mfa_device_id` |
| `ChallengeResponseInvalidEvent` | `LOGIN_ERROR` | `CHALLENGE_RESPONSE_INVALID` | `push_mfa_invalid_response` | `push_mfa_challenge_id`, `push_mfa_credential_id`, `push_mfa_reason` |
| `EnrollmentCompletedEvent` | `UPDATE_CREDENTIAL` | `ENROLLMENT_COMPLETED` | - | `credential_type`, `push_mfa_challenge_id`, `push_mfa_credential_id`, `push_mfa_device_id`, `push_mfa_device_type` |
| `KeyRotatedEvent` | `UPDATE_CREDENTIAL` | `KEY_ROTATED` | - | `credential_type`, `push_mfa_credential_id`, `push_mfa_device_id` |
| `KeyRotationDeniedEvent` | `UPDATE_CREDENTIAL_ERROR` | `KEY_ROTATION_DENIED` | `push_mfa_key_rotation_denied` | `credential_type`, `push_mfa_credential_id`, `push_mfa_reason` |
| `DpopAuthenticationFailedEvent` | `LOGIN_ERROR` | `DPOP_AUTHENTICATION_FAILED` | `push_mfa_dpop_auth_failed` | `push_mfa_credential_id`, `push_mfa_reason`, `push_mfa_http_method`, `push_mfa_request_path` |
| `UserLockedOutEvent` | `LOGIN_ERROR` | `USER_LOCKED_OUT` | `push_mfa_user_locked_out` | `push_mfa_credential_id`, `push_mfa_device_id` |

- **Event Type Value**: Value of the `push_mfa_event_type` detail; use this to distinguish events sharing the same Keycloak EventType
- **Error Code**: Value returned by `Event.getError()` for error events
- **Additional Detail Keys**: Other keys present in `Event.getDetails()` map (all events also include `push_mfa_event_type`; credential-related events include Keycloak's `credential_type` set to `push-mfa`)

> **Brute force protector note:** The `LOGIN_ERROR` events above are fired by the event bridge when processing device-side REST API responses. These are separate from the authenticator flow, where only an explicit **challenge denied** triggers `context.failureChallenge()`. Non-credential errors (challenge expiry, rate limits, internal errors) use `context.challenge()` and do **not** increment the brute force failure counter. See [Security — Brute Force Protector Compatibility](security.md#brute-force-protector-compatibility) for details.

#### Logging Listener (`log`)

Logs all events at INFO level with DEBUG details. Configure Keycloak's logging to see the output:

```properties
quarkus.log.category."de.arbeitsagentur.keycloak.push.spi.event".level=DEBUG
```

### Using PushMfaEventDetails Constants

The `PushMfaEventDetails` class provides constants for all detail keys, event types, and error codes. Use these when processing Push MFA events in your Keycloak `EventListenerProvider`:

```java
import de.arbeitsagentur.keycloak.push.spi.event.PushMfaEventDetails;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;

public void onEvent(Event event) {
    if (event.getType() == EventType.UPDATE_CREDENTIAL) {
        String eventType = event.getDetails().get(PushMfaEventDetails.EVENT_TYPE);

        if (PushMfaEventDetails.EventTypes.ENROLLMENT_COMPLETED.equals(eventType)) {
            // New Push MFA credential was created
            String deviceId = event.getDetails().get(PushMfaEventDetails.DEVICE_ID);
            String deviceType = event.getDetails().get(PushMfaEventDetails.DEVICE_TYPE);
            // ...
        } else if (PushMfaEventDetails.EventTypes.KEY_ROTATED.equals(eventType)) {
            // Existing credential's key was rotated
            // ...
        }
    }
}
```

**Detail Key Constants** (`PushMfaEventDetails.*`):

| Constant | String Value |
|----------|--------------|
| `EVENT_TYPE` | `push_mfa_event_type` |
| `CHALLENGE_ID` | `push_mfa_challenge_id` |
| `CHALLENGE_TYPE` | `push_mfa_challenge_type` |
| `DEVICE_CREDENTIAL_ID` | `push_mfa_credential_id` |
| `DEVICE_ID` | `push_mfa_device_id` |
| `DEVICE_TYPE` | `push_mfa_device_type` |
| `USER_VERIFICATION` | `push_mfa_user_verification` |
| `REASON` | `push_mfa_reason` |
| `HTTP_METHOD` | `push_mfa_http_method` |
| `REQUEST_PATH` | `push_mfa_request_path` |

**Event Type Constants** (`PushMfaEventDetails.EventTypes.*`):

| Constant | String Value |
|----------|--------------|
| `CHALLENGE_CREATED` | `CHALLENGE_CREATED` |
| `CHALLENGE_ACCEPTED` | `CHALLENGE_ACCEPTED` |
| `CHALLENGE_DENIED` | `CHALLENGE_DENIED` |
| `CHALLENGE_RESPONSE_INVALID` | `CHALLENGE_RESPONSE_INVALID` |
| `ENROLLMENT_COMPLETED` | `ENROLLMENT_COMPLETED` |
| `KEY_ROTATED` | `KEY_ROTATED` |
| `KEY_ROTATION_DENIED` | `KEY_ROTATION_DENIED` |
| `DPOP_AUTHENTICATION_FAILED` | `DPOP_AUTHENTICATION_FAILED` |
| `USER_LOCKED_OUT` | `USER_LOCKED_OUT` |

**Error Code Constants** (`PushMfaEventDetails.ErrorCodes.*`):

| Constant | String Value |
|----------|--------------|
| `CHALLENGE_DENIED` | `push_mfa_challenge_denied` |
| `INVALID_RESPONSE` | `push_mfa_invalid_response` |
| `KEY_ROTATION_DENIED` | `push_mfa_key_rotation_denied` |
| `DPOP_AUTH_FAILED` | `push_mfa_dpop_auth_failed` |
| `USER_LOCKED_OUT` | `push_mfa_user_locked_out` |

### Multiple Active Listeners

The Push MFA Event SPI supports multiple active listeners simultaneously. All registered listeners receive every event, wrapped in exception handling to prevent one failing listener from affecting others. This means you can:

- Enable the Keycloak event bridge for Admin Console visibility
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

Your custom listener will run alongside any other active listeners (logging listener and, if enabled, the Keycloak event bridge).

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
