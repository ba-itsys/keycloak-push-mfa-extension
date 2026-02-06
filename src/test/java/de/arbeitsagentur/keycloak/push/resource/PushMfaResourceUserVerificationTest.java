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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.spi.PushMfaEventListener;
import de.arbeitsagentur.keycloak.push.spi.event.ChallengeResponseInvalidEvent;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.ForbiddenException;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.mockito.Mockito;

class PushMfaResourceUserVerificationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void verifyUserVerificationRejectsPinWithoutLeadingZeros() {
        KeycloakSession session = buildMockSession();
        PushMfaResource resource = new PushMfaResource(session);
        PushChallenge challenge = buildPinChallenge("0123");
        ObjectNode payload = MAPPER.createObjectNode().put("userVerification", "123");

        assertThrows(
                ForbiddenException.class,
                () -> resource.verifyUserVerification(session, challenge, payload, "cred-id"));
    }

    @Test
    void verifyUserVerificationAcceptsCorrectPin() {
        KeycloakSession session = buildMockSession();
        PushMfaResource resource = new PushMfaResource(session);
        PushChallenge challenge = buildPinChallenge("0123");
        ObjectNode payload = MAPPER.createObjectNode().put("userVerification", "0123");

        // Should not throw any exception
        resource.verifyUserVerification(session, challenge, payload, "cred-id");
    }

    @Test
    void buildUserVerificationInfoForPinOmitsValue() {
        KeycloakSession session = buildMockSession();
        PushMfaResource resource = new PushMfaResource(session);
        PushChallenge challenge = buildPinChallenge("012345");

        PushMfaResource.UserVerificationInfo info = resource.buildUserVerificationInfo(challenge);
        assertEquals(PushMfaConstants.USER_VERIFICATION_PIN, info.type());
        assertEquals(6, info.pinLength());
        assertNull(info.numbers());
    }

    private KeycloakSession buildMockSession() {
        KeycloakSession session = Mockito.mock(KeycloakSession.class);
        SingleUseObjectProvider singleUse = Mockito.mock(SingleUseObjectProvider.class);
        Mockito.when(session.singleUseObjects()).thenReturn(singleUse);
        return session;
    }

    @Test
    void verifyUserVerification_numberMatch_acceptsCorrectSelection() {
        KeycloakSession session = buildMockSession();
        PushMfaResource resource = new PushMfaResource(session);
        PushChallenge challenge = buildNumberMatchChallenge("42", List.of("17", "42", "89"));
        ObjectNode payload = MAPPER.createObjectNode().put("userVerification", "42");

        // Should not throw any exception
        resource.verifyUserVerification(session, challenge, payload, "cred-id");
    }

    @Test
    void verifyUserVerification_numberMatch_rejectsWrongSelection() {
        KeycloakSession session = buildMockSession();
        PushMfaResource resource = new PushMfaResource(session);
        PushChallenge challenge = buildNumberMatchChallenge("42", List.of("17", "42", "89"));
        ObjectNode payload = MAPPER.createObjectNode().put("userVerification", "17");

        assertThrows(
                ForbiddenException.class,
                () -> resource.verifyUserVerification(session, challenge, payload, "cred-id"));
    }

    @Test
    void buildUserVerificationInfo_numberMatch_returnsNumbersList() {
        KeycloakSession session = buildMockSession();
        PushMfaResource resource = new PushMfaResource(session);
        List<String> numbers = List.of("12", "56", "78");
        PushChallenge challenge = buildNumberMatchChallenge("56", numbers);

        PushMfaResource.UserVerificationInfo info = resource.buildUserVerificationInfo(challenge);
        assertEquals(PushMfaConstants.USER_VERIFICATION_NUMBER_MATCH, info.type());
        assertEquals(numbers, info.numbers());
        assertNull(info.pinLength());
    }

    @Test
    void verifyUserVerification_noneMode_skipsValidation() {
        KeycloakSession session = buildMockSession();
        PushMfaResource resource = new PushMfaResource(session);
        PushChallenge challenge = buildNoneChallenge();
        ObjectNode payload = MAPPER.createObjectNode();

        // Should not throw any exception even without userVerification in payload
        resource.verifyUserVerification(session, challenge, payload, "cred-id");
    }

    @Test
    void verifyUserVerificationMismatchEventUsesPassedCredentialId() {
        // The challenge has a Keycloak CredentialModel ID as credentialId,
        // but the event should use the app-level credentialId passed as parameter
        String keycloakModelId = "keycloak-model-uuid";
        String appCredentialId = "app-credential-id";

        KeycloakSession session = buildMockSession();

        // Capture the ChallengeResponseInvalidEvent via a mock listener
        AtomicReference<ChallengeResponseInvalidEvent> capturedEvent = new AtomicReference<>();
        PushMfaEventListener listener = Mockito.mock(PushMfaEventListener.class);
        doAnswer(inv -> {
                    capturedEvent.set(inv.getArgument(0));
                    return null;
                })
                .when(listener)
                .onChallengeResponseInvalid(any());
        Mockito.when(session.getAllProviders(PushMfaEventListener.class)).thenReturn(Set.of(listener));

        PushMfaResource resource = new PushMfaResource(session);
        // Build challenge with the Keycloak model UUID as its credentialId
        PushChallenge challenge = buildPinChallengeWithCredentialId("0123", keycloakModelId);
        ObjectNode payload = MAPPER.createObjectNode().put("userVerification", "wrong");

        assertThrows(
                ForbiddenException.class,
                () -> resource.verifyUserVerification(session, challenge, payload, appCredentialId));

        assertNotNull(capturedEvent.get(), "ChallengeResponseInvalidEvent should have been fired");
        assertEquals(
                appCredentialId,
                capturedEvent.get().credentialId(),
                "Event credentialId should be the app-level credential ID, not the Keycloak model UUID");
    }

    private PushChallenge buildPinChallengeWithCredentialId(String pin, String credentialId) {
        return new PushChallenge(
                "challenge-123",
                "realm-id",
                "user-id",
                new byte[] {1, 2, 3},
                credentialId,
                "client-id",
                "watch-secret",
                "root-session",
                Instant.now().plusSeconds(300),
                PushChallenge.Type.AUTHENTICATION,
                PushChallengeStatus.PENDING,
                Instant.now(),
                null,
                PushChallenge.UserVerificationMode.PIN,
                pin,
                List.of());
    }

    private PushChallenge buildPinChallenge(String pin) {
        return new PushChallenge(
                "challenge-123",
                "realm-id",
                "user-id",
                new byte[] {1, 2, 3},
                "cred-1",
                "client-id",
                "watch-secret",
                "root-session",
                Instant.now().plusSeconds(300),
                PushChallenge.Type.AUTHENTICATION,
                PushChallengeStatus.PENDING,
                Instant.now(),
                null,
                PushChallenge.UserVerificationMode.PIN,
                pin,
                List.of());
    }

    private PushChallenge buildNumberMatchChallenge(String correctNumber, List<String> options) {
        return new PushChallenge(
                "challenge-123",
                "realm-id",
                "user-id",
                new byte[] {1, 2, 3},
                "cred-1",
                "client-id",
                "watch-secret",
                "root-session",
                Instant.now().plusSeconds(300),
                PushChallenge.Type.AUTHENTICATION,
                PushChallengeStatus.PENDING,
                Instant.now(),
                null,
                PushChallenge.UserVerificationMode.NUMBER_MATCH,
                correctNumber,
                options);
    }

    private PushChallenge buildNoneChallenge() {
        return new PushChallenge(
                "challenge-123",
                "realm-id",
                "user-id",
                new byte[] {1, 2, 3},
                "cred-1",
                "client-id",
                "watch-secret",
                "root-session",
                Instant.now().plusSeconds(300),
                PushChallenge.Type.AUTHENTICATION,
                PushChallengeStatus.PENDING,
                Instant.now(),
                null,
                PushChallenge.UserVerificationMode.NONE,
                null,
                List.of());
    }
}
