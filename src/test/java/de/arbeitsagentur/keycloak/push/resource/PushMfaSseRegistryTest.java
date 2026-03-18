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

package de.arbeitsagentur.keycloak.push.resource;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;

class PushMfaSseRegistryTest {

    private static final String REALM_ID = "realm-1";
    private static final String ROOT_SESSION_ID = "root-session-1";

    @Test
    void authenticationChallengeWithMissingRootSessionIsInactive() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmProvider realmProvider = mock(RealmProvider.class);
        AuthenticationSessionProvider authSessions = mock(AuthenticationSessionProvider.class);
        RealmModel realm = mock(RealmModel.class);

        when(session.realms()).thenReturn(realmProvider);
        when(session.authenticationSessions()).thenReturn(authSessions);
        when(realmProvider.getRealm(REALM_ID)).thenReturn(realm);
        when(authSessions.getRootAuthenticationSession(realm, ROOT_SESSION_ID)).thenReturn(null);

        PushChallenge challenge = authenticationChallenge(ROOT_SESSION_ID);

        assertFalse(PushMfaSseRegistry.isAuthenticationSessionActive(session, challenge));
    }

    @Test
    void authenticationChallengeWithExistingRootSessionIsActive() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmProvider realmProvider = mock(RealmProvider.class);
        AuthenticationSessionProvider authSessions = mock(AuthenticationSessionProvider.class);
        RealmModel realm = mock(RealmModel.class);
        RootAuthenticationSessionModel rootSession = mock(RootAuthenticationSessionModel.class);

        when(session.realms()).thenReturn(realmProvider);
        when(session.authenticationSessions()).thenReturn(authSessions);
        when(realmProvider.getRealm(REALM_ID)).thenReturn(realm);
        when(authSessions.getRootAuthenticationSession(realm, ROOT_SESSION_ID)).thenReturn(rootSession);

        PushChallenge challenge = authenticationChallenge(ROOT_SESSION_ID);

        assertTrue(PushMfaSseRegistry.isAuthenticationSessionActive(session, challenge));
    }

    @Test
    void authenticationChallengeWithoutRootSessionIdStaysActive() {
        KeycloakSession session = mock(KeycloakSession.class);

        PushChallenge challenge = authenticationChallenge(null);

        assertTrue(PushMfaSseRegistry.isAuthenticationSessionActive(session, challenge));
    }

    private PushChallenge authenticationChallenge(String rootSessionId) {
        Instant now = Instant.now();
        return new PushChallenge(
                "challenge-1",
                REALM_ID,
                "user-1",
                new byte[0],
                "credential-1",
                "client-1",
                "watch-secret",
                rootSessionId,
                now.plusSeconds(60),
                PushChallenge.Type.AUTHENTICATION,
                PushChallengeStatus.PENDING,
                now,
                null,
                PushChallenge.UserVerificationMode.NONE,
                null,
                List.of());
    }
}
