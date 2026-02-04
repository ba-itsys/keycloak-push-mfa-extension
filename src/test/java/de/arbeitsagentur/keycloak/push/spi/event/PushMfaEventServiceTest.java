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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.spi.PushMfaEventListener;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;

class PushMfaEventServiceTest {

    private KeycloakSession session;
    private TestEventListener listener1;
    private TestEventListener listener2;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        listener1 = new TestEventListener();
        listener2 = new TestEventListener();
    }

    @Test
    void fireDispatchesToAllListeners() {
        when(session.getAllProviders(PushMfaEventListener.class)).thenReturn(Set.of(listener1, listener2));

        ChallengeCreatedEvent event = new ChallengeCreatedEvent(
                "realm-1",
                "user-1",
                "challenge-1",
                PushChallenge.Type.AUTHENTICATION,
                "cred-1",
                "client-1",
                PushChallenge.UserVerificationMode.NONE,
                Instant.now().plusSeconds(120),
                Instant.now());

        PushMfaEventService.fire(session, event);

        assertEquals(1, listener1.genericEvents.size());
        assertEquals(1, listener1.challengeCreatedEvents.size());
        assertEquals(1, listener2.genericEvents.size());
        assertEquals(1, listener2.challengeCreatedEvents.size());
    }

    @Test
    void fireHandlesNullSession() {
        KeyRotatedEvent event = new KeyRotatedEvent("r", "u", "c", "d", Instant.now());
        assertDoesNotThrow(() -> PushMfaEventService.fire(null, event));
    }

    @Test
    void fireHandlesNullEvent() {
        assertDoesNotThrow(() -> PushMfaEventService.fire(session, null));
    }

    @Test
    void fireHandlesEmptyListeners() {
        when(session.getAllProviders(PushMfaEventListener.class)).thenReturn(Set.of());

        ChallengeAcceptedEvent event = new ChallengeAcceptedEvent(
                "realm-1",
                "user-1",
                "challenge-1",
                PushChallenge.Type.AUTHENTICATION,
                "cred-1",
                "client-1",
                "device-1",
                Instant.now());

        assertDoesNotThrow(() -> PushMfaEventService.fire(session, event));
    }

    @Test
    void fireIsolatesListenerExceptions() {
        PushMfaEventListener failingListener = new PushMfaEventListener() {
            @Override
            public void onEvent(PushMfaEvent event) {
                throw new RuntimeException("Listener failed");
            }
        };

        when(session.getAllProviders(PushMfaEventListener.class)).thenReturn(Set.of(failingListener, listener1));

        ChallengeDeniedEvent event = new ChallengeDeniedEvent(
                "realm-1",
                "user-1",
                "challenge-1",
                PushChallenge.Type.AUTHENTICATION,
                "cred-1",
                "client-1",
                "device-1",
                Instant.now());

        assertDoesNotThrow(() -> PushMfaEventService.fire(session, event));
        assertEquals(1, listener1.challengeDeniedEvents.size());
    }

    @Test
    void fireDispatchesToCorrectSpecificHandler() {
        when(session.getAllProviders(PushMfaEventListener.class)).thenReturn(Set.of(listener1));

        // Test each event type dispatches to correct handler
        PushMfaEventService.fire(
                session,
                new ChallengeCreatedEvent(
                        "r",
                        "u",
                        "c",
                        PushChallenge.Type.AUTHENTICATION,
                        null,
                        null,
                        null,
                        Instant.now(),
                        Instant.now()));
        PushMfaEventService.fire(
                session,
                new ChallengeAcceptedEvent(
                        "r", "u", "c", PushChallenge.Type.AUTHENTICATION, null, null, null, Instant.now()));
        PushMfaEventService.fire(
                session,
                new ChallengeDeniedEvent(
                        "r", "u", "c", PushChallenge.Type.AUTHENTICATION, null, null, null, Instant.now()));
        PushMfaEventService.fire(
                session, new ChallengeResponseInvalidEvent("r", "u", "c", null, "reason", Instant.now()));
        PushMfaEventService.fire(
                session, new EnrollmentCompletedEvent("r", "u", "c", "cred", "dev", "ios", Instant.now()));
        PushMfaEventService.fire(session, new KeyRotatedEvent("r", "u", "cred", "dev", Instant.now()));
        PushMfaEventService.fire(session, new KeyRotationDeniedEvent("r", "u", "cred", "reason", Instant.now()));
        PushMfaEventService.fire(
                session, new DpopAuthenticationFailedEvent("r", "u", "cred", "reason", "POST", "/path", Instant.now()));

        assertEquals(8, listener1.genericEvents.size());
        assertEquals(1, listener1.challengeCreatedEvents.size());
        assertEquals(1, listener1.challengeAcceptedEvents.size());
        assertEquals(1, listener1.challengeDeniedEvents.size());
        assertEquals(1, listener1.challengeResponseInvalidEvents.size());
        assertEquals(1, listener1.enrollmentCompletedEvents.size());
        assertEquals(1, listener1.keyRotatedEvents.size());
        assertEquals(1, listener1.keyRotationDeniedEvents.size());
        assertEquals(1, listener1.dpopAuthenticationFailedEvents.size());
    }

    /** Test listener that records all events for verification. */
    static class TestEventListener implements PushMfaEventListener {
        final List<PushMfaEvent> genericEvents = new ArrayList<>();
        final List<ChallengeCreatedEvent> challengeCreatedEvents = new ArrayList<>();
        final List<ChallengeAcceptedEvent> challengeAcceptedEvents = new ArrayList<>();
        final List<ChallengeDeniedEvent> challengeDeniedEvents = new ArrayList<>();
        final List<ChallengeResponseInvalidEvent> challengeResponseInvalidEvents = new ArrayList<>();
        final List<EnrollmentCompletedEvent> enrollmentCompletedEvents = new ArrayList<>();
        final List<KeyRotatedEvent> keyRotatedEvents = new ArrayList<>();
        final List<KeyRotationDeniedEvent> keyRotationDeniedEvents = new ArrayList<>();
        final List<DpopAuthenticationFailedEvent> dpopAuthenticationFailedEvents = new ArrayList<>();

        @Override
        public void onEvent(PushMfaEvent event) {
            genericEvents.add(event);
        }

        @Override
        public void onChallengeCreated(ChallengeCreatedEvent event) {
            challengeCreatedEvents.add(event);
        }

        @Override
        public void onChallengeAccepted(ChallengeAcceptedEvent event) {
            challengeAcceptedEvents.add(event);
        }

        @Override
        public void onChallengeDenied(ChallengeDeniedEvent event) {
            challengeDeniedEvents.add(event);
        }

        @Override
        public void onChallengeResponseInvalid(ChallengeResponseInvalidEvent event) {
            challengeResponseInvalidEvents.add(event);
        }

        @Override
        public void onEnrollmentCompleted(EnrollmentCompletedEvent event) {
            enrollmentCompletedEvents.add(event);
        }

        @Override
        public void onKeyRotated(KeyRotatedEvent event) {
            keyRotatedEvents.add(event);
        }

        @Override
        public void onKeyRotationDenied(KeyRotationDeniedEvent event) {
            keyRotationDeniedEvents.add(event);
        }

        @Override
        public void onDpopAuthenticationFailed(DpopAuthenticationFailedEvent event) {
            dpopAuthenticationFailedEvents.add(event);
        }
    }
}
