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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.spi.PushMfaEventListener;
import de.arbeitsagentur.keycloak.push.spi.PushNotificationSender;
import de.arbeitsagentur.keycloak.push.spi.event.ChallengeCreatedEvent;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.credential.CredentialModel;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;

class ChallengeIssuerTest {

    private static final String REALM_ID = "test-realm-id";
    private static final String REALM_NAME = "test-realm";
    private static final String USER_ID = "test-user-id";
    private static final String CREDENTIAL_ID = "test-credential-id";
    private static final String CLIENT_ID = "test-client";
    private static final String ROOT_SESSION_ID = "test-root-session";
    private static final Duration CHALLENGE_TTL = Duration.ofSeconds(120);

    private AuthenticationFlowContext context;
    private PushChallengeStore challengeStore;
    private PushCredentialData credentialData;
    private CredentialModel credential;
    private KeycloakSession session;
    private RealmModel realm;
    private UserModel user;
    private AuthenticationSessionModel authSession;
    private AuthenticatorConfigModel authenticatorConfig;
    private UriInfo uriInfo;
    private KeyManager keyManager;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(ChallengeIssuerTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        context = mock(AuthenticationFlowContext.class);
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        user = mock(UserModel.class);
        authSession = mock(AuthenticationSessionModel.class);
        authenticatorConfig = mock(AuthenticatorConfigModel.class);
        uriInfo = mock(UriInfo.class);
        keyManager = mock(KeyManager.class);

        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUser()).thenReturn(user);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfig);
        when(context.getUriInfo()).thenReturn(uriInfo);

        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn(REALM_NAME);
        when(realm.getDefaultSignatureAlgorithm()).thenReturn("RS256");
        when(user.getId()).thenReturn(USER_ID);
        when(uriInfo.getBaseUri()).thenReturn(URI.create("https://keycloak.example.com/"));

        when(session.keys()).thenReturn(keyManager);
        when(session.getProvider(eq(PushNotificationSender.class), anyString()))
                .thenReturn(mock(PushNotificationSender.class));
        when(session.getAllProviders(any())).thenReturn(Set.of());

        // Set up in-memory SingleUseObjectProvider
        InMemorySingleUseObjectProvider singleUseObjects = new InMemorySingleUseObjectProvider();
        when(session.singleUseObjects()).thenReturn(singleUseObjects);

        KeyWrapper keyWrapper = createTestKeyWrapper();
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);

        challengeStore = new PushChallengeStore(session);

        credentialData = new PushCredentialData(
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"test\",\"y\":\"test\"}",
                System.currentTimeMillis(),
                "ios",
                "push-provider-id",
                "log",
                CREDENTIAL_ID,
                "device-id");

        credential = new CredentialModel();
        credential.setId(CREDENTIAL_ID);
    }

    @Test
    void issueCreatesValidChallengeWithDefaultUserVerificationMode() {
        when(authenticatorConfig.getConfig()).thenReturn(new HashMap<>());

        ChallengeIssuer.IssuedChallenge result = ChallengeIssuer.issue(
                context, challengeStore, credentialData, credential, CHALLENGE_TTL, CLIENT_ID, ROOT_SESSION_ID);

        assertNotNull(result);
        assertNotNull(result.challenge());
        assertNotNull(result.confirmToken());

        PushChallenge challenge = result.challenge();
        assertEquals(REALM_ID, challenge.getRealmId());
        assertEquals(USER_ID, challenge.getUserId());
        assertEquals(CREDENTIAL_ID, challenge.getCredentialId());
        assertEquals(CLIENT_ID, challenge.getClientId());
        assertEquals(ROOT_SESSION_ID, challenge.getRootSessionId());
        assertEquals(PushChallenge.Type.AUTHENTICATION, challenge.getType());
        assertEquals(PushChallengeStatus.PENDING, challenge.getStatus());
        assertEquals(PushChallenge.UserVerificationMode.NONE, challenge.getUserVerificationMode());
        assertNull(challenge.getUserVerificationValue());
        assertTrue(challenge.getUserVerificationOptions().isEmpty());
    }

    @Test
    void issueCreatesChallengeWithNumberMatchMode() {
        Map<String, String> config = new HashMap<>();
        config.put(PushMfaConstants.USER_VERIFICATION_CONFIG, PushMfaConstants.USER_VERIFICATION_NUMBER_MATCH);
        when(authenticatorConfig.getConfig()).thenReturn(config);

        ChallengeIssuer.IssuedChallenge result = ChallengeIssuer.issue(
                context, challengeStore, credentialData, credential, CHALLENGE_TTL, CLIENT_ID, ROOT_SESSION_ID);

        PushChallenge challenge = result.challenge();
        assertEquals(PushChallenge.UserVerificationMode.NUMBER_MATCH, challenge.getUserVerificationMode());
        assertNotNull(challenge.getUserVerificationValue());
        assertEquals(3, challenge.getUserVerificationOptions().size());
        assertTrue(challenge.getUserVerificationOptions().contains(challenge.getUserVerificationValue()));
    }

    @Test
    void issueCreatesChallengeWithPinMode() {
        Map<String, String> config = new HashMap<>();
        config.put(PushMfaConstants.USER_VERIFICATION_CONFIG, PushMfaConstants.USER_VERIFICATION_PIN);
        config.put(PushMfaConstants.USER_VERIFICATION_PIN_LENGTH_CONFIG, "6");
        when(authenticatorConfig.getConfig()).thenReturn(config);

        ChallengeIssuer.IssuedChallenge result = ChallengeIssuer.issue(
                context, challengeStore, credentialData, credential, CHALLENGE_TTL, CLIENT_ID, ROOT_SESSION_ID);

        PushChallenge challenge = result.challenge();
        assertEquals(PushChallenge.UserVerificationMode.PIN, challenge.getUserVerificationMode());
        assertNotNull(challenge.getUserVerificationValue());
        assertEquals(6, challenge.getUserVerificationValue().length());
        assertTrue(challenge.getUserVerificationOptions().isEmpty());
    }

    @Test
    void issueCreatesChallengeWithDefaultPinLength() {
        Map<String, String> config = new HashMap<>();
        config.put(PushMfaConstants.USER_VERIFICATION_CONFIG, PushMfaConstants.USER_VERIFICATION_PIN);
        when(authenticatorConfig.getConfig()).thenReturn(config);

        ChallengeIssuer.IssuedChallenge result = ChallengeIssuer.issue(
                context, challengeStore, credentialData, credential, CHALLENGE_TTL, CLIENT_ID, ROOT_SESSION_ID);

        PushChallenge challenge = result.challenge();
        assertEquals(PushChallenge.UserVerificationMode.PIN, challenge.getUserVerificationMode());
        assertEquals(
                PushMfaConstants.DEFAULT_USER_VERIFICATION_PIN_LENGTH,
                challenge.getUserVerificationValue().length());
    }

    @Test
    void issueGeneratesUniqueChallengeIds() {
        when(authenticatorConfig.getConfig()).thenReturn(new HashMap<>());

        Set<String> challengeIds = new HashSet<>();
        for (int i = 0; i < 10; i++) {
            ChallengeIssuer.IssuedChallenge result = ChallengeIssuer.issue(
                    context, challengeStore, credentialData, credential, CHALLENGE_TTL, CLIENT_ID, ROOT_SESSION_ID);
            challengeIds.add(result.challenge().getId());
        }

        assertEquals(10, challengeIds.size(), "All challenge IDs should be unique");
    }

    @Test
    void issueSetsChallengeExpirationTime() {
        when(authenticatorConfig.getConfig()).thenReturn(new HashMap<>());

        Instant beforeIssue = Instant.now();
        ChallengeIssuer.IssuedChallenge result = ChallengeIssuer.issue(
                context, challengeStore, credentialData, credential, CHALLENGE_TTL, CLIENT_ID, ROOT_SESSION_ID);
        Instant afterIssue = Instant.now();

        PushChallenge challenge = result.challenge();
        Instant expiresAt = challenge.getExpiresAt();

        assertTrue(expiresAt.isAfter(beforeIssue.plus(CHALLENGE_TTL).minusSeconds(1)));
        assertTrue(expiresAt.isBefore(afterIssue.plus(CHALLENGE_TTL).plusSeconds(1)));
    }

    @Test
    void issueStoresChallengeIdInAuthSession() {
        when(authenticatorConfig.getConfig()).thenReturn(new HashMap<>());

        ChallengeIssuer.IssuedChallenge result = ChallengeIssuer.issue(
                context, challengeStore, credentialData, credential, CHALLENGE_TTL, CLIENT_ID, ROOT_SESSION_ID);

        verify(authSession)
                .setAuthNote(
                        eq(PushMfaConstants.CHALLENGE_NOTE),
                        eq(result.challenge().getId()));
        verify(authSession)
                .setClientNote(
                        eq(PushMfaConstants.CHALLENGE_NOTE),
                        eq(result.challenge().getId()));
    }

    @Test
    void issueStoresWatchSecretInAuthSession() {
        when(authenticatorConfig.getConfig()).thenReturn(new HashMap<>());

        ChallengeIssuer.issue(
                context, challengeStore, credentialData, credential, CHALLENGE_TTL, CLIENT_ID, ROOT_SESSION_ID);

        verify(authSession).setAuthNote(eq(PushMfaConstants.CHALLENGE_WATCH_SECRET_NOTE), anyString());
    }

    @Test
    void issueGeneratesConfirmToken() {
        when(authenticatorConfig.getConfig()).thenReturn(new HashMap<>());

        ChallengeIssuer.IssuedChallenge result = ChallengeIssuer.issue(
                context, challengeStore, credentialData, credential, CHALLENGE_TTL, CLIENT_ID, ROOT_SESSION_ID);

        assertNotNull(result.confirmToken());
        assertTrue(result.confirmToken().contains("."), "Confirm token should be a JWT");
        String[] parts = result.confirmToken().split("\\.");
        assertEquals(3, parts.length, "JWT should have header, payload, and signature");
    }

    @Test
    void issueHandlesNullAuthenticatorConfig() {
        when(context.getAuthenticatorConfig()).thenReturn(null);

        ChallengeIssuer.IssuedChallenge result = ChallengeIssuer.issue(
                context, challengeStore, credentialData, credential, CHALLENGE_TTL, CLIENT_ID, ROOT_SESSION_ID);

        assertNotNull(result);
        assertEquals(PushChallenge.UserVerificationMode.NONE, result.challenge().getUserVerificationMode());
    }

    @Test
    void issueHandlesNullConfigMap() {
        when(authenticatorConfig.getConfig()).thenReturn(null);

        ChallengeIssuer.IssuedChallenge result = ChallengeIssuer.issue(
                context, challengeStore, credentialData, credential, CHALLENGE_TTL, CLIENT_ID, ROOT_SESSION_ID);

        assertNotNull(result);
        assertEquals(PushChallenge.UserVerificationMode.NONE, result.challenge().getUserVerificationMode());
    }

    @Test
    void issueWithDifferentTtlValues() {
        when(authenticatorConfig.getConfig()).thenReturn(new HashMap<>());

        Duration shortTtl = Duration.ofSeconds(30);
        Duration longTtl = Duration.ofMinutes(10);

        Instant before = Instant.now();

        ChallengeIssuer.IssuedChallenge shortResult = ChallengeIssuer.issue(
                context, challengeStore, credentialData, credential, shortTtl, CLIENT_ID, ROOT_SESSION_ID);
        ChallengeIssuer.IssuedChallenge longResult = ChallengeIssuer.issue(
                context, challengeStore, credentialData, credential, longTtl, CLIENT_ID, ROOT_SESSION_ID);

        Instant after = Instant.now();

        assertTrue(shortResult
                .challenge()
                .getExpiresAt()
                .isBefore(longResult.challenge().getExpiresAt()));
        assertTrue(shortResult
                .challenge()
                .getExpiresAt()
                .isAfter(before.plus(shortTtl).minusSeconds(1)));
        assertTrue(longResult
                .challenge()
                .getExpiresAt()
                .isBefore(after.plus(longTtl).plusSeconds(1)));
    }

    @Test
    void numberMatchOptionsAreUnique() {
        Map<String, String> config = new HashMap<>();
        config.put(PushMfaConstants.USER_VERIFICATION_CONFIG, PushMfaConstants.USER_VERIFICATION_NUMBER_MATCH);
        when(authenticatorConfig.getConfig()).thenReturn(config);

        for (int i = 0; i < 10; i++) {
            ChallengeIssuer.IssuedChallenge result = ChallengeIssuer.issue(
                    context, challengeStore, credentialData, credential, CHALLENGE_TTL, CLIENT_ID, ROOT_SESSION_ID);

            List<String> options = result.challenge().getUserVerificationOptions();
            assertEquals(3, options.size());
            assertEquals(3, new HashSet<>(options).size(), "All number match options should be unique");
        }
    }

    @Test
    void pinContainsOnlyDigits() {
        Map<String, String> config = new HashMap<>();
        config.put(PushMfaConstants.USER_VERIFICATION_CONFIG, PushMfaConstants.USER_VERIFICATION_PIN);
        config.put(PushMfaConstants.USER_VERIFICATION_PIN_LENGTH_CONFIG, "8");
        when(authenticatorConfig.getConfig()).thenReturn(config);

        for (int i = 0; i < 10; i++) {
            ChallengeIssuer.IssuedChallenge result = ChallengeIssuer.issue(
                    context, challengeStore, credentialData, credential, CHALLENGE_TTL, CLIENT_ID, ROOT_SESSION_ID);

            String pin = result.challenge().getUserVerificationValue();
            assertTrue(pin.matches("^\\d{8}$"), "PIN should contain exactly 8 digits");
        }
    }

    @Test
    void issueWithExplicitNoneUserVerification() {
        Map<String, String> config = new HashMap<>();
        config.put(PushMfaConstants.USER_VERIFICATION_CONFIG, PushMfaConstants.USER_VERIFICATION_NONE);
        when(authenticatorConfig.getConfig()).thenReturn(config);

        ChallengeIssuer.IssuedChallenge result = ChallengeIssuer.issue(
                context, challengeStore, credentialData, credential, CHALLENGE_TTL, CLIENT_ID, ROOT_SESSION_ID);

        assertEquals(PushChallenge.UserVerificationMode.NONE, result.challenge().getUserVerificationMode());
        assertNull(result.challenge().getUserVerificationValue());
        assertTrue(result.challenge().getUserVerificationOptions().isEmpty());
    }

    @Test
    void eventCredentialIdMatchesTokenCredentialId() throws Exception {
        // Use DIFFERENT IDs to expose the mismatch:
        // - credential.getId() returns the Keycloak CredentialModel UUID
        // - credentialData.getCredentialId() returns the app-level credential ID
        String keycloakModelId = "keycloak-model-uuid";
        String appCredentialId = "app-credential-id";

        credential.setId(keycloakModelId);
        PushCredentialData differentCredentialData = new PushCredentialData(
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"test\",\"y\":\"test\"}",
                System.currentTimeMillis(),
                "ios",
                "push-provider-id",
                "log",
                appCredentialId,
                "device-id");

        when(authenticatorConfig.getConfig()).thenReturn(new HashMap<>());

        // Capture the ChallengeCreatedEvent via a mock listener
        AtomicReference<ChallengeCreatedEvent> capturedEvent = new AtomicReference<>();
        PushMfaEventListener listener = mock(PushMfaEventListener.class);
        doAnswer(inv -> {
                    capturedEvent.set(inv.getArgument(0));
                    return null;
                })
                .when(listener)
                .onChallengeCreated(any());
        when(session.getAllProviders(PushMfaEventListener.class)).thenReturn(Set.of(listener));

        ChallengeIssuer.IssuedChallenge result = ChallengeIssuer.issue(
                context,
                challengeStore,
                differentCredentialData,
                credential,
                CHALLENGE_TTL,
                CLIENT_ID,
                ROOT_SESSION_ID);

        // Decode the token payload to get the credId claim
        String[] jwtParts = result.confirmToken().split("\\.");
        String payloadJson = new String(Base64.getUrlDecoder().decode(jwtParts[1]));
        JsonNode payload = new ObjectMapper().readTree(payloadJson);
        String tokenCredentialId = payload.get("credId").asText();

        // The event's credentialId should match the token's credId,
        // so that consumers can reconstruct the token from event data
        assertNotNull(capturedEvent.get(), "ChallengeCreatedEvent should have been fired");
        assertEquals(
                tokenCredentialId,
                capturedEvent.get().credentialId(),
                "ChallengeCreatedEvent.credentialId() should match the token's credId claim, "
                        + "but event has '" + capturedEvent.get().credentialId()
                        + "' while token has '" + tokenCredentialId + "'");
    }

    private KeyWrapper createTestKeyWrapper() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setKid("test-key-id");
        keyWrapper.setAlgorithm("RS256");
        keyWrapper.setPrivateKey(keyPair.getPrivate());
        keyWrapper.setPublicKey(keyPair.getPublic());
        return keyWrapper;
    }

    /**
     * In-memory implementation of SingleUseObjectProvider for testing.
     */
    private static final class InMemorySingleUseObjectProvider implements SingleUseObjectProvider {

        private final Map<String, Map<String, String>> data = new HashMap<>();

        @Override
        public void put(String key, long lifespanSeconds, Map<String, String> value) {
            data.put(key, new HashMap<>(value));
        }

        @Override
        public Map<String, String> get(String key) {
            Map<String, String> value = data.get(key);
            return value == null ? null : new HashMap<>(value);
        }

        @Override
        public Map<String, String> remove(String key) {
            Map<String, String> removed = data.remove(key);
            return removed == null ? null : new HashMap<>(removed);
        }

        @Override
        public boolean replace(String key, Map<String, String> value) {
            if (!data.containsKey(key)) {
                return false;
            }
            data.put(key, new HashMap<>(value));
            return true;
        }

        @Override
        public boolean putIfAbsent(String key, long lifespanSeconds) {
            if (data.containsKey(key)) {
                return false;
            }
            data.put(key, new HashMap<>());
            return true;
        }

        @Override
        public boolean contains(String key) {
            return data.containsKey(key);
        }

        @Override
        public void close() {
            // no-op
        }
    }
}
