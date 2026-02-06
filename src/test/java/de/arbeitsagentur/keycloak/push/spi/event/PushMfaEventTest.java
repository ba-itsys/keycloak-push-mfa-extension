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

import static de.arbeitsagentur.keycloak.push.spi.event.PushMfaEventDetails.EventTypes;
import static org.junit.jupiter.api.Assertions.*;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class PushMfaEventTest {

    private static final String REALM_ID = "test-realm";
    private static final String USER_ID = "user-123";
    private static final String CHALLENGE_ID = "challenge-456";
    private static final String CREDENTIAL_ID = "cred-789";
    private static final String CLIENT_ID = "test-client";
    private static final String DEVICE_ID = "device-abc";
    private static final Instant TIMESTAMP = Instant.parse("2026-01-15T10:30:00Z");
    private static final Instant EXPIRES_AT = Instant.parse("2026-01-15T10:32:00Z");

    @Test
    void challengeCreatedEventHasCorrectType() {
        ChallengeCreatedEvent event = new ChallengeCreatedEvent(
                REALM_ID,
                USER_ID,
                CHALLENGE_ID,
                PushChallenge.Type.AUTHENTICATION,
                CREDENTIAL_ID,
                CLIENT_ID,
                PushChallenge.UserVerificationMode.PIN,
                EXPIRES_AT,
                TIMESTAMP);

        assertEquals(EventTypes.CHALLENGE_CREATED, event.eventType());
        assertEquals(REALM_ID, event.realmId());
        assertEquals(USER_ID, event.userId());
        assertEquals(CHALLENGE_ID, event.challengeId());
        assertEquals(PushChallenge.Type.AUTHENTICATION, event.challengeType());
        assertEquals(CREDENTIAL_ID, event.credentialId());
        assertEquals(CLIENT_ID, event.clientId());
        assertEquals(PushChallenge.UserVerificationMode.PIN, event.userVerificationMode());
        assertEquals(EXPIRES_AT, event.expiresAt());
        assertEquals(TIMESTAMP, event.timestamp());
    }

    @Test
    void challengeCreatedEventAllowsNullOptionalFields() {
        ChallengeCreatedEvent event = new ChallengeCreatedEvent(
                REALM_ID,
                USER_ID,
                CHALLENGE_ID,
                PushChallenge.Type.ENROLLMENT,
                null, // credentialId
                null, // clientId
                PushChallenge.UserVerificationMode.NONE,
                EXPIRES_AT,
                TIMESTAMP);

        assertNull(event.credentialId());
        assertNull(event.clientId());
        assertEquals(PushChallenge.Type.ENROLLMENT, event.challengeType());
    }

    @Test
    void challengeAcceptedEventHasCorrectType() {
        ChallengeAcceptedEvent event = new ChallengeAcceptedEvent(
                REALM_ID,
                USER_ID,
                CHALLENGE_ID,
                PushChallenge.Type.AUTHENTICATION,
                CREDENTIAL_ID,
                CLIENT_ID,
                DEVICE_ID,
                TIMESTAMP);

        assertEquals(EventTypes.CHALLENGE_ACCEPTED, event.eventType());
        assertEquals(DEVICE_ID, event.deviceId());
    }

    @Test
    void challengeDeniedEventHasCorrectType() {
        ChallengeDeniedEvent event = new ChallengeDeniedEvent(
                REALM_ID,
                USER_ID,
                CHALLENGE_ID,
                PushChallenge.Type.AUTHENTICATION,
                CREDENTIAL_ID,
                CLIENT_ID,
                DEVICE_ID,
                TIMESTAMP);

        assertEquals(EventTypes.CHALLENGE_DENIED, event.eventType());
    }

    @Test
    void challengeResponseInvalidEventHasCorrectType() {
        String reason = "Invalid signature";
        ChallengeResponseInvalidEvent event =
                new ChallengeResponseInvalidEvent(REALM_ID, USER_ID, CHALLENGE_ID, CREDENTIAL_ID, reason, TIMESTAMP);

        assertEquals(EventTypes.CHALLENGE_RESPONSE_INVALID, event.eventType());
        assertEquals(reason, event.reason());
    }

    @Test
    void enrollmentCompletedEventHasCorrectType() {
        String deviceType = "iOS";
        EnrollmentCompletedEvent event = new EnrollmentCompletedEvent(
                REALM_ID, USER_ID, CHALLENGE_ID, CREDENTIAL_ID, DEVICE_ID, deviceType, TIMESTAMP);

        assertEquals(EventTypes.ENROLLMENT_COMPLETED, event.eventType());
        assertEquals(deviceType, event.deviceType());
    }

    @Test
    void keyRotatedEventHasCorrectType() {
        KeyRotatedEvent event = new KeyRotatedEvent(REALM_ID, USER_ID, CREDENTIAL_ID, DEVICE_ID, TIMESTAMP);

        assertEquals(EventTypes.KEY_ROTATED, event.eventType());
    }

    @Test
    void keyRotationDeniedEventHasCorrectType() {
        String reason = "Invalid public key format";
        KeyRotationDeniedEvent event = new KeyRotationDeniedEvent(REALM_ID, USER_ID, CREDENTIAL_ID, reason, TIMESTAMP);

        assertEquals(EventTypes.KEY_ROTATION_DENIED, event.eventType());
        assertEquals(reason, event.reason());
    }

    @Test
    void dpopAuthenticationFailedEventHasCorrectType() {
        String reason = "DPoP proof signature invalid";
        String httpMethod = "POST";
        String requestPath = "/realms/test/push-mfa/login/pending";
        DpopAuthenticationFailedEvent event = new DpopAuthenticationFailedEvent(
                REALM_ID, USER_ID, CREDENTIAL_ID, reason, httpMethod, requestPath, TIMESTAMP);

        assertEquals(EventTypes.DPOP_AUTHENTICATION_FAILED, event.eventType());
        assertEquals(reason, event.reason());
        assertEquals(httpMethod, event.httpMethod());
        assertEquals(requestPath, event.requestPath());
    }

    @Test
    void dpopAuthenticationFailedEventAllowsNullUserAndCredential() {
        DpopAuthenticationFailedEvent event = new DpopAuthenticationFailedEvent(
                REALM_ID, null, null, "Invalid access token", "GET", "/path", TIMESTAMP);

        assertNull(event.userId());
        assertNull(event.credentialId());
        assertEquals(REALM_ID, event.realmId());
    }

    @Test
    void eventsAreImmutableRecords() {
        ChallengeCreatedEvent event1 = new ChallengeCreatedEvent(
                REALM_ID,
                USER_ID,
                CHALLENGE_ID,
                PushChallenge.Type.AUTHENTICATION,
                CREDENTIAL_ID,
                CLIENT_ID,
                PushChallenge.UserVerificationMode.NONE,
                EXPIRES_AT,
                TIMESTAMP);

        ChallengeCreatedEvent event2 = new ChallengeCreatedEvent(
                REALM_ID,
                USER_ID,
                CHALLENGE_ID,
                PushChallenge.Type.AUTHENTICATION,
                CREDENTIAL_ID,
                CLIENT_ID,
                PushChallenge.UserVerificationMode.NONE,
                EXPIRES_AT,
                TIMESTAMP);

        // Records should be equal if all fields match
        assertEquals(event1, event2);
        assertEquals(event1.hashCode(), event2.hashCode());
    }

    @Test
    void allEventTypesImplementPushMfaEvent() {
        PushMfaEvent[] events = {
            new ChallengeCreatedEvent(
                    REALM_ID,
                    USER_ID,
                    CHALLENGE_ID,
                    PushChallenge.Type.AUTHENTICATION,
                    null,
                    null,
                    null,
                    EXPIRES_AT,
                    TIMESTAMP),
            new ChallengeAcceptedEvent(
                    REALM_ID, USER_ID, CHALLENGE_ID, PushChallenge.Type.AUTHENTICATION, null, null, null, TIMESTAMP),
            new ChallengeDeniedEvent(
                    REALM_ID, USER_ID, CHALLENGE_ID, PushChallenge.Type.AUTHENTICATION, null, null, null, TIMESTAMP),
            new ChallengeResponseInvalidEvent(REALM_ID, USER_ID, CHALLENGE_ID, null, "reason", TIMESTAMP),
            new EnrollmentCompletedEvent(REALM_ID, USER_ID, CHALLENGE_ID, CREDENTIAL_ID, DEVICE_ID, "ios", TIMESTAMP),
            new KeyRotatedEvent(REALM_ID, USER_ID, CREDENTIAL_ID, DEVICE_ID, TIMESTAMP),
            new KeyRotationDeniedEvent(REALM_ID, USER_ID, CREDENTIAL_ID, "reason", TIMESTAMP),
            new DpopAuthenticationFailedEvent(REALM_ID, USER_ID, CREDENTIAL_ID, "reason", "POST", "/path", TIMESTAMP)
        };

        for (PushMfaEvent event : events) {
            assertNotNull(event.eventType(), "eventType should not be null");
            assertNotNull(event.realmId(), "realmId should not be null");
            // userId can be null for some events (e.g., DpopAuthenticationFailedEvent)
            assertNotNull(event.timestamp(), "timestamp should not be null");
        }
    }
}
