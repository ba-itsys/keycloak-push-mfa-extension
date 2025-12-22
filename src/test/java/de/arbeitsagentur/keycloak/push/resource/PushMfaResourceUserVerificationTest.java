package de.arbeitsagentur.keycloak.push.resource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.ForbiddenException;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.mockito.Mockito;

class PushMfaResourceUserVerificationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void verifyUserVerificationRejectsPinWithoutLeadingZeros() {
        PushMfaResource resource = buildResource();
        PushChallenge challenge = buildPinChallenge("0123");
        ObjectNode payload = MAPPER.createObjectNode().put("userVerification", "123");

        assertThrows(ForbiddenException.class, () -> resource.verifyUserVerification(challenge, payload));
    }

    @Test
    void buildUserVerificationInfoForPinOmitsValue() {
        PushMfaResource resource = buildResource();
        PushChallenge challenge = buildPinChallenge("012345");

        PushMfaResource.UserVerificationInfo info = resource.buildUserVerificationInfo(challenge);
        assertEquals(PushMfaConstants.USER_VERIFICATION_PIN, info.type());
        assertEquals(6, info.pinLength());
        assertNull(info.numbers());
    }

    private PushMfaResource buildResource() {
        KeycloakSession session = Mockito.mock(KeycloakSession.class);
        SingleUseObjectProvider singleUse = Mockito.mock(SingleUseObjectProvider.class);
        Mockito.when(session.singleUseObjects()).thenReturn(singleUse);
        return new PushMfaResource(session);
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
}
