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

import static de.arbeitsagentur.keycloak.push.spi.event.KeycloakEventBridgeListener.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.spi.event.KeycloakEventBridgeListener.KeycloakEvent;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;

class KeycloakEventBridgeListenerTest {

    private KeycloakSession session;
    private RealmProvider realmProvider;
    private List<KeycloakEvent> captured;
    private KeycloakEventBridgeListener listener;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        realmProvider = mock(RealmProvider.class);
        captured = new ArrayList<>();

        when(session.realms()).thenReturn(realmProvider);
        when(realmProvider.getRealm("test-realm")).thenReturn(mock(RealmModel.class));

        listener = new KeycloakEventBridgeListener(session, captured::add);
    }

    @Test
    void factoryCreatesListener() {
        var factory = new KeycloakEventBridgeListenerFactory();
        assertEquals("keycloak-event-bridge", factory.getId());
        assertInstanceOf(KeycloakEventBridgeListener.class, factory.create(session));
    }

    @Test
    void onChallengeCreated() {
        listener.onChallengeCreated(new ChallengeCreatedEvent(
                "test-realm", "user-1", "chal-1", PushChallenge.Type.AUTHENTICATION,
                "cred-1", "client-1", PushChallenge.UserVerificationMode.NUMBER_MATCH,
                Instant.now().plusSeconds(120), Instant.now()));

        assertEquals(1, captured.size());
        var event = captured.get(0);
        assertEquals(EventType.CUSTOM_REQUIRED_ACTION, event.eventType());
        assertEquals("user-1", event.userId());
        assertEquals("client-1", event.clientId());
        assertNull(event.error());
        assertEquals("CHALLENGE_CREATED", event.details().get(DETAIL_EVENT_TYPE));
        assertEquals("AUTHENTICATION", event.details().get(DETAIL_CHALLENGE_TYPE));
        assertEquals("NUMBER_MATCH", event.details().get(DETAIL_USER_VERIFICATION));
    }

    @Test
    void onChallengeAccepted() {
        listener.onChallengeAccepted(new ChallengeAcceptedEvent(
                "test-realm", "user-1", "chal-1", PushChallenge.Type.AUTHENTICATION,
                "cred-1", "client-1", "device-1", Instant.now()));

        var event = captured.get(0);
        assertEquals(EventType.LOGIN, event.eventType());
        assertNull(event.error());
        assertEquals("CHALLENGE_ACCEPTED", event.details().get(DETAIL_EVENT_TYPE));
        assertEquals("device-1", event.details().get(DETAIL_DEVICE_ID));
    }

    @Test
    void onChallengeDenied() {
        listener.onChallengeDenied(new ChallengeDeniedEvent(
                "test-realm", "user-1", "chal-1", PushChallenge.Type.AUTHENTICATION,
                "cred-1", "client-1", "device-1", Instant.now()));

        var event = captured.get(0);
        assertEquals(EventType.LOGIN_ERROR, event.eventType());
        assertEquals(ERROR_CHALLENGE_DENIED, event.error());
        assertEquals("CHALLENGE_DENIED", event.details().get(DETAIL_EVENT_TYPE));
    }

    @Test
    void onChallengeResponseInvalid() {
        listener.onChallengeResponseInvalid(new ChallengeResponseInvalidEvent(
                "test-realm", "user-1", "chal-1", "cred-1", "Bad signature", Instant.now()));

        var event = captured.get(0);
        assertEquals(EventType.LOGIN_ERROR, event.eventType());
        assertEquals(ERROR_INVALID_RESPONSE, event.error());
        assertEquals("Bad signature", event.details().get(DETAIL_REASON));
    }

    @Test
    void onEnrollmentCompleted() {
        listener.onEnrollmentCompleted(new EnrollmentCompletedEvent(
                "test-realm", "user-1", "chal-1", "cred-1", "device-1", "iOS", Instant.now()));

        var event = captured.get(0);
        assertEquals(EventType.CUSTOM_REQUIRED_ACTION, event.eventType());
        assertNull(event.error());
        assertEquals("ENROLLMENT_COMPLETED", event.details().get(DETAIL_EVENT_TYPE));
        assertEquals("iOS", event.details().get(DETAIL_DEVICE_TYPE));
    }

    @Test
    void onKeyRotated() {
        listener.onKeyRotated(new KeyRotatedEvent("test-realm", "user-1", "cred-1", "device-1", Instant.now()));

        var event = captured.get(0);
        assertEquals(EventType.UPDATE_CREDENTIAL, event.eventType());
        assertNull(event.error());
        assertEquals("KEY_ROTATED", event.details().get(DETAIL_EVENT_TYPE));
        assertEquals("push-mfa", event.details().get("credential_type"));
    }

    @Test
    void onKeyRotationDenied() {
        listener.onKeyRotationDenied(new KeyRotationDeniedEvent(
                "test-realm", "user-1", "cred-1", "Invalid key", Instant.now()));

        var event = captured.get(0);
        assertEquals(EventType.UPDATE_CREDENTIAL_ERROR, event.eventType());
        assertEquals(ERROR_KEY_ROTATION_DENIED, event.error());
        assertEquals("push-mfa", event.details().get("credential_type"));
    }

    @Test
    void onDpopAuthenticationFailed() {
        listener.onDpopAuthenticationFailed(new DpopAuthenticationFailedEvent(
                "test-realm", "user-1", "cred-1", "Signature mismatch", "POST", "/path", Instant.now()));

        var event = captured.get(0);
        assertEquals(EventType.LOGIN_ERROR, event.eventType());
        assertEquals(ERROR_DPOP_AUTH_FAILED, event.error());
        assertEquals("POST", event.details().get(DETAIL_HTTP_METHOD));
        assertEquals("/path", event.details().get(DETAIL_REQUEST_PATH));
    }

    @Test
    void omitsNullOptionalFields() {
        listener.onChallengeCreated(new ChallengeCreatedEvent(
                "test-realm", "user-1", "chal-1", null, null, null, null, Instant.now(), Instant.now()));

        var details = captured.get(0).details();
        assertFalse(details.containsKey(DETAIL_CHALLENGE_TYPE));
        assertFalse(details.containsKey(DETAIL_CREDENTIAL_ID));
        assertFalse(details.containsKey(DETAIL_USER_VERIFICATION));
    }

    @Test
    void skipsEmitWhenRealmNotFound() {
        when(realmProvider.getRealm("unknown")).thenReturn(null);

        listener.onChallengeCreated(new ChallengeCreatedEvent(
                "unknown", "user-1", "chal-1", null, null, null, null, Instant.now(), Instant.now()));
        listener.onChallengeCreated(new ChallengeCreatedEvent(
                null, "user-1", "chal-1", null, null, null, null, Instant.now(), Instant.now()));

        assertTrue(captured.isEmpty());
    }
}
