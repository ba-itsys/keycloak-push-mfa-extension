/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.arbeitsagentur.keycloak.push.spi.event;

import de.arbeitsagentur.keycloak.push.spi.PushMfaEventListener;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import org.jboss.logging.Logger;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Bridges Push MFA events to Keycloak's standard event system.
 *
 * <p>Events become visible in Admin Console, Event Store, and standard EventListenerProviders.
 */
class KeycloakEventBridgeListener implements PushMfaEventListener {

    private static final Logger LOG = Logger.getLogger(KeycloakEventBridgeListener.class);

    private final KeycloakSession session;
    private final Consumer<KeycloakEvent> eventSender;

    KeycloakEventBridgeListener(KeycloakSession session) {
        this(session, event -> sendEvent(session, event));
    }

    /** Constructor for testing - allows injecting a custom event sender. */
    KeycloakEventBridgeListener(KeycloakSession session, Consumer<KeycloakEvent> eventSender) {
        this.session = session;
        this.eventSender = eventSender;
    }

    @Override
    public void onChallengeCreated(ChallengeCreatedEvent event) {
        var details = new EventDetails()
                .add(PushMfaEventDetails.EVENT_TYPE, PushMfaEventDetails.EventTypes.CHALLENGE_CREATED)
                .add(PushMfaEventDetails.CHALLENGE_ID, event.challengeId())
                .add(PushMfaEventDetails.CHALLENGE_TYPE, event.challengeType())
                .add(PushMfaEventDetails.CREDENTIAL_ID, event.credentialId())
                .add(PushMfaEventDetails.USER_VERIFICATION, event.userVerificationMode());

        emit(event.realmId(), event.userId(), event.clientId(), EventType.CUSTOM_REQUIRED_ACTION, null, details);
    }

    @Override
    public void onChallengeAccepted(ChallengeAcceptedEvent event) {
        var details = new EventDetails()
                .add(PushMfaEventDetails.EVENT_TYPE, PushMfaEventDetails.EventTypes.CHALLENGE_ACCEPTED)
                .add(PushMfaEventDetails.CHALLENGE_ID, event.challengeId())
                .add(PushMfaEventDetails.CHALLENGE_TYPE, event.challengeType())
                .add(PushMfaEventDetails.CREDENTIAL_ID, event.credentialId())
                .add(PushMfaEventDetails.DEVICE_ID, event.deviceId());

        emit(event.realmId(), event.userId(), event.clientId(), EventType.LOGIN, null, details);
    }

    @Override
    public void onChallengeDenied(ChallengeDeniedEvent event) {
        var details = new EventDetails()
                .add(PushMfaEventDetails.EVENT_TYPE, PushMfaEventDetails.EventTypes.CHALLENGE_DENIED)
                .add(PushMfaEventDetails.CHALLENGE_ID, event.challengeId())
                .add(PushMfaEventDetails.CHALLENGE_TYPE, event.challengeType())
                .add(PushMfaEventDetails.CREDENTIAL_ID, event.credentialId())
                .add(PushMfaEventDetails.DEVICE_ID, event.deviceId());

        emit(
                event.realmId(),
                event.userId(),
                event.clientId(),
                EventType.LOGIN_ERROR,
                PushMfaEventDetails.ErrorCodes.CHALLENGE_DENIED,
                details);
    }

    @Override
    public void onChallengeResponseInvalid(ChallengeResponseInvalidEvent event) {
        var details = new EventDetails()
                .add(PushMfaEventDetails.EVENT_TYPE, PushMfaEventDetails.EventTypes.CHALLENGE_RESPONSE_INVALID)
                .add(PushMfaEventDetails.CHALLENGE_ID, event.challengeId())
                .add(PushMfaEventDetails.CREDENTIAL_ID, event.credentialId())
                .add(PushMfaEventDetails.REASON, event.reason());

        emit(
                event.realmId(),
                event.userId(),
                null,
                EventType.LOGIN_ERROR,
                PushMfaEventDetails.ErrorCodes.INVALID_RESPONSE,
                details);
    }

    @Override
    public void onEnrollmentCompleted(EnrollmentCompletedEvent event) {
        var details = new EventDetails()
                .add(Details.CREDENTIAL_TYPE, PushMfaConstants.CREDENTIAL_TYPE)
                .add(PushMfaEventDetails.EVENT_TYPE, PushMfaEventDetails.EventTypes.ENROLLMENT_COMPLETED)
                .add(PushMfaEventDetails.CHALLENGE_ID, event.challengeId())
                .add(PushMfaEventDetails.CREDENTIAL_ID, event.credentialId())
                .add(PushMfaEventDetails.DEVICE_ID, event.deviceId())
                .add(PushMfaEventDetails.DEVICE_TYPE, event.deviceType());

        emit(event.realmId(), event.userId(), null, EventType.UPDATE_CREDENTIAL, null, details);
    }

    @Override
    public void onKeyRotated(KeyRotatedEvent event) {
        var details = new EventDetails()
                .add(Details.CREDENTIAL_TYPE, PushMfaConstants.CREDENTIAL_TYPE)
                .add(PushMfaEventDetails.EVENT_TYPE, PushMfaEventDetails.EventTypes.KEY_ROTATED)
                .add(PushMfaEventDetails.CREDENTIAL_ID, event.credentialId())
                .add(PushMfaEventDetails.DEVICE_ID, event.deviceId());

        emit(event.realmId(), event.userId(), null, EventType.UPDATE_CREDENTIAL, null, details);
    }

    @Override
    public void onKeyRotationDenied(KeyRotationDeniedEvent event) {
        var details = new EventDetails()
                .add(Details.CREDENTIAL_TYPE, PushMfaConstants.CREDENTIAL_TYPE)
                .add(PushMfaEventDetails.EVENT_TYPE, PushMfaEventDetails.EventTypes.KEY_ROTATION_DENIED)
                .add(PushMfaEventDetails.CREDENTIAL_ID, event.credentialId())
                .add(PushMfaEventDetails.REASON, event.reason());

        emit(
                event.realmId(),
                event.userId(),
                null,
                EventType.UPDATE_CREDENTIAL_ERROR,
                PushMfaEventDetails.ErrorCodes.KEY_ROTATION_DENIED,
                details);
    }

    @Override
    public void onDpopAuthenticationFailed(DpopAuthenticationFailedEvent event) {
        var details = new EventDetails()
                .add(PushMfaEventDetails.EVENT_TYPE, PushMfaEventDetails.EventTypes.DPOP_AUTHENTICATION_FAILED)
                .add(PushMfaEventDetails.CREDENTIAL_ID, event.credentialId())
                .add(PushMfaEventDetails.REASON, event.reason())
                .add(PushMfaEventDetails.HTTP_METHOD, event.httpMethod())
                .add(PushMfaEventDetails.REQUEST_PATH, event.requestPath());

        emit(
                event.realmId(),
                event.userId(),
                null,
                EventType.LOGIN_ERROR,
                PushMfaEventDetails.ErrorCodes.DPOP_AUTH_FAILED,
                details);
    }

    private void emit(
            String realmId, String userId, String clientId, EventType type, String error, EventDetails details) {
        if (realmId == null) {
            LOG.debug("Cannot emit Keycloak event: realmId is null");
            return;
        }
        if (session.realms().getRealm(realmId) == null) {
            LOG.debugf("Cannot emit Keycloak event: realm not found for id=%s", realmId);
            return;
        }
        eventSender.accept(new KeycloakEvent(realmId, userId, clientId, type, error, details.map));
    }

    private static void sendEvent(KeycloakSession session, KeycloakEvent event) {
        RealmModel realm = session.realms().getRealm(event.realmId());
        if (realm == null) {
            return;
        }

        EventBuilder builder =
                new EventBuilder(realm, session, session.getContext().getConnection());
        builder.event(event.eventType());

        event.details().forEach((key, value) -> {
            if (value != null) {
                builder.detail(key, value);
            }
        });

        if (event.clientId() != null) {
            builder.client(event.clientId());
        }

        if (event.userId() != null) {
            UserModel user = session.users().getUserById(realm, event.userId());
            if (user != null) {
                builder.user(user);
            } else {
                builder.user(event.userId());
            }
        }

        if (event.error() != null) {
            builder.error(event.error());
        } else {
            builder.success();
        }
    }

    /** Helper for building detail maps with null handling. */
    private static class EventDetails {
        final Map<String, String> map = new HashMap<>();

        EventDetails add(String key, Object value) {
            if (value != null) {
                map.put(key, value instanceof Enum<?> e ? e.name() : value.toString());
            }
            return this;
        }
    }

    /** Keycloak event data for testability. */
    record KeycloakEvent(
            String realmId,
            String userId,
            String clientId,
            EventType eventType,
            String error,
            Map<String, String> details) {}
}
