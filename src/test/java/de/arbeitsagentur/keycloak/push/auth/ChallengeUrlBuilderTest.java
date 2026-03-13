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

package de.arbeitsagentur.keycloak.push.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.support.TestKeycloakSupport;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;

class ChallengeUrlBuilderTest {

    @Test
    void buildWatchUrlUsesChallengeSecretOrSessionFallback() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        RealmModel realm = mock(RealmModel.class);
        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);

        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUriInfo()).thenReturn(uriInfo);
        when(realm.getName()).thenReturn("demo");
        when(uriInfo.getBaseUriBuilder()).thenAnswer(invocation -> UriBuilder.fromUri("https://kc.example/"));

        assertEquals(
                "https://kc.example/realms/demo/push-mfa/login/challenges/challenge-123/events?secret=watch-secret",
                ChallengeUrlBuilder.buildWatchUrl(
                        context,
                        challenge("challenge-123", "watch-secret", PushChallenge.UserVerificationMode.NONE, null)));

        when(authSession.getAuthNote(PushMfaConstants.CHALLENGE_WATCH_SECRET_NOTE))
                .thenReturn("note-secret");
        assertEquals(
                "https://kc.example/realms/demo/push-mfa/login/challenges/challenge-123/events?secret=note-secret",
                ChallengeUrlBuilder.buildWatchUrl(
                        context, challenge("challenge-123", null, PushChallenge.UserVerificationMode.NONE, null)));
    }

    @Test
    void buildWatchUrlReturnsNullForMissingInputs() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        when(context.getAuthenticationSession()).thenReturn(authSession);

        assertNull(ChallengeUrlBuilder.buildWatchUrl(context, null));
        assertNull(ChallengeUrlBuilder.buildWatchUrl(
                context, challenge("", "secret", PushChallenge.UserVerificationMode.NONE, null)));
        assertNull(ChallengeUrlBuilder.buildWatchUrl(
                context, challenge("cid", null, PushChallenge.UserVerificationMode.NONE, null)));
    }

    @Test
    void buildPushUriHandlesNormalAndFallbackCases() {
        assertEquals(
                "https://app.example/confirm?token=abc",
                ChallengeUrlBuilder.buildPushUri("https://app.example/confirm", "abc"));
        assertNull(ChallengeUrlBuilder.buildPushUri("https://app.example/confirm", null));
        assertEquals("token-123", ChallengeUrlBuilder.buildPushUri(null, "token-123"));
        assertEquals("token-123", ChallengeUrlBuilder.buildPushUri("://bad-uri", "token-123"));
    }

    @Test
    void buildSameDeviceTokenIncludesVerificationOnlyWhenEnabled() throws Exception {
        PushCredentialData data = new PushCredentialData("{}", 1L, "mobile", "provider", "fcm", "cred-1", "device-1");
        PushChallenge challenge = challenge("cid", "secret", PushChallenge.UserVerificationMode.PIN, "1234");

        AuthenticationFlowContext disabledContext = mockContext(Map.of());
        assertEquals(
                "confirm-token",
                ChallengeUrlBuilder.buildSameDeviceToken(disabledContext, challenge, data, "confirm-token"));
        assertEquals(
                "confirm-token",
                ChallengeUrlBuilder.buildSameDeviceToken(disabledContext, null, data, "confirm-token"));
        assertNull(ChallengeUrlBuilder.buildSameDeviceToken(disabledContext, challenge, data, null));

        AuthenticationFlowContext enabledContext =
                mockContext(Map.of(PushMfaConstants.SAME_DEVICE_INCLUDE_USER_VERIFICATION_CONFIG, "true"));
        String token = ChallengeUrlBuilder.buildSameDeviceToken(enabledContext, challenge, data, "confirm-token");

        assertNotEquals("confirm-token", token);
    }

    private static AuthenticationFlowContext mockContext(Map<String, String> configValues) throws Exception {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(configValues);
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        KeyManager keyManager = mock(KeyManager.class);

        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUriInfo()).thenReturn(uriInfo);
        when(session.keys()).thenReturn(keyManager);
        when(keyManager.getActiveKey(any(), eq(KeyUse.SIG), any()))
                .thenReturn(TestKeycloakSupport.rsaSigningKey("kid-1"));
        when(realm.getName()).thenReturn("demo");
        when(realm.getDefaultSignatureAlgorithm()).thenReturn(Algorithm.RS256.toString());
        when(uriInfo.getBaseUri()).thenReturn(URI.create("https://kc.example/"));
        when(uriInfo.getBaseUriBuilder()).thenReturn(UriBuilder.fromUri("https://kc.example/"));
        return context;
    }

    private static PushChallenge challenge(
            String id,
            String watchSecret,
            PushChallenge.UserVerificationMode verificationMode,
            String verificationValue) {
        return new PushChallenge(
                id,
                "realm-1",
                "user-1",
                new byte[] {1, 2, 3},
                "kc-cred-1",
                "client-1",
                watchSecret,
                "root-1",
                Instant.now().plusSeconds(60),
                PushChallenge.Type.AUTHENTICATION,
                PushChallengeStatus.PENDING,
                Instant.now(),
                null,
                verificationMode,
                verificationValue,
                List.of("12", "34", "56"));
    }
}
