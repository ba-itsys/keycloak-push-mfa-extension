package de.arbeitsagentur.keycloak.push.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.token.PushConfirmTokenBuilder;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.Mockito;

class PushMfaAuthenticatorTest {

    private final KeycloakSession session = Mockito.mock(KeycloakSession.class);
    private final RealmModel realm = Mockito.mock(RealmModel.class);
    private final KeyManager keyManager = Mockito.mock(KeyManager.class);
    private KeyWrapper keyWrapper;

    @BeforeEach
    void setUp() throws Exception {
        Mockito.reset(session, realm, keyManager);
        keyWrapper = buildKeyWrapper("test-kid", Algorithm.RS256.toString());
        Mockito.when(session.keys()).thenReturn(keyManager);
        Mockito.when(realm.getDefaultSignatureAlgorithm()).thenReturn(Algorithm.RS256.toString());
        Mockito.when(keyManager.getActiveKey(
                        Mockito.any(), Mockito.eq(KeyUse.SIG), Mockito.eq(Algorithm.RS256.toString())))
                .thenReturn(keyWrapper);
        Mockito.when(realm.getName()).thenReturn("demo");
    }

    @Test
    void numberMatchOptionsAreUnique() {
        PushMfaAuthenticator authenticator = new PushMfaAuthenticator();

        for (int i = 0; i < 25; i++) {
            List<String> options = authenticator.generateNumberMatchOptions();

            assertEquals(3, options.size(), () -> "Expected 3 number-match options but got: " + options);
            assertEquals(3, new HashSet<>(options).size(), () -> "Expected unique options but got: " + options);
            for (String option : options) {
                assertTrue(
                        option.matches("^(0|[1-9][0-9]?)$"),
                        () -> "Expected number-match option 0-99 but got: " + option);
            }
        }
    }

    @Test
    void numberMatchSelectionIsApproximatelyUniform() {
        PushMfaAuthenticator authenticator = new PushMfaAuthenticator();

        int samples = 150;
        int[] counts = new int[3];
        for (int attempt = 0; attempt < samples; attempt++) {
            List<String> options = authenticator.generateNumberMatchOptions();
            String displayed = authenticator.selectNumberMatchValue(options);
            int index = options.indexOf(displayed);
            assertTrue(index >= 0, () -> "Displayed value not found in options: " + displayed + " vs " + options);
            counts[index]++;
        }

        // Regression test for randomness:
        // The shown number should be equally likely to be in position 0, 1, or 2 of the 3-item list.
        // We create many challenges, count which position the shown number had, and then run a chi-square test.
        // Why 18.42? With 3 buckets the test has df=2; 18.42 is the 99.99th percentile (p=0.0001).
        final double chiSquareCritical = 18.42;
        double expected = samples / 3.0;
        double chiSquare = 0.0;
        for (int count : counts) {
            double diff = count - expected;
            chiSquare += (diff * diff) / expected;
        }
        assertTrue(
                chiSquare <= chiSquareCritical,
                "Expected roughly uniform distribution across indices but got counts=" + counts[0] + "," + counts[1]
                        + "," + counts[2] + " (chiSquare=" + chiSquare + ")");

        assertTrue(
                counts[0] > 0 && counts[1] > 0 && counts[2] > 0,
                () -> "All indices should appear at least once but got counts=" + counts[0] + "," + counts[1] + ","
                        + counts[2]);
    }

    @Test
    void generatePinKeepsLeadingZeros() {
        PushMfaAuthenticator authenticator = new PushMfaAuthenticator();
        Random deterministic = new Random() {
            private int index;
            private final int[] values = {0, 1, 2, 3};

            @Override
            public int nextInt(int bound) {
                int value = values[index % values.length];
                index++;
                return value;
            }
        };

        assertEquals("0123", authenticator.generatePin(4, deterministic));
    }

    @Test
    void resolvePinLengthUsesConfigAndBounds() {
        PushMfaAuthenticator authenticator = new PushMfaAuthenticator();
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        Map<String, String> configMap = new HashMap<>();
        config.setConfig(configMap);

        configMap.put(PushMfaConstants.USER_VERIFICATION_PIN_LENGTH_CONFIG, "6");
        assertEquals(6, authenticator.resolvePinLength(config));

        configMap.put(PushMfaConstants.USER_VERIFICATION_PIN_LENGTH_CONFIG, "0");
        assertEquals(PushMfaConstants.DEFAULT_USER_VERIFICATION_PIN_LENGTH, authenticator.resolvePinLength(config));

        configMap.put(PushMfaConstants.USER_VERIFICATION_PIN_LENGTH_CONFIG, "18");
        assertEquals(12, authenticator.resolvePinLength(config));

        configMap.put(PushMfaConstants.USER_VERIFICATION_PIN_LENGTH_CONFIG, "not-a-number");
        assertEquals(PushMfaConstants.DEFAULT_USER_VERIFICATION_PIN_LENGTH, authenticator.resolvePinLength(config));
    }

    @Test
    void sameDeviceTokenIncludesUserVerificationWhenEnabled() throws Exception {
        PushMfaAuthenticator authenticator = new PushMfaAuthenticator();
        PushChallenge challenge = buildChallenge("0421");
        PushCredentialData credentialData = credentialData("cred-1");
        URI baseUri = URI.create("http://localhost:8080/");
        AuthenticationFlowContext context = buildContext(true, baseUri);
        String confirmToken = PushConfirmTokenBuilder.build(
                session, realm, credentialData.getCredentialId(), challenge.getId(), challenge.getExpiresAt(), baseUri);

        String sameDeviceToken = authenticator.resolveSameDeviceToken(context, challenge, credentialData, confirmToken);

        SignedJWT sameDeviceJwt = SignedJWT.parse(sameDeviceToken);
        JWTClaimsSet sameDeviceClaims = sameDeviceJwt.getJWTClaimsSet();
        assertEquals("0421", sameDeviceClaims.getStringClaim("userVerification"));

        SignedJWT confirmJwt = SignedJWT.parse(confirmToken);
        assertNull(confirmJwt.getJWTClaimsSet().getClaim("userVerification"));
    }

    @Test
    void sameDeviceTokenDefaultsToConfirmTokenWhenDisabled() throws Exception {
        PushMfaAuthenticator authenticator = new PushMfaAuthenticator();
        PushChallenge challenge = buildChallenge("0421");
        PushCredentialData credentialData = credentialData("cred-1");
        URI baseUri = URI.create("http://localhost:8080/");
        AuthenticationFlowContext context = buildContext(false, baseUri);
        String confirmToken = PushConfirmTokenBuilder.build(
                session, realm, credentialData.getCredentialId(), challenge.getId(), challenge.getExpiresAt(), baseUri);

        String sameDeviceToken = authenticator.resolveSameDeviceToken(context, challenge, credentialData, confirmToken);

        assertEquals(confirmToken, sameDeviceToken);
    }

    private AuthenticationFlowContext buildContext(boolean includeUserVerification, URI baseUri) {
        AuthenticationFlowContext context = Mockito.mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(
                PushMfaConstants.SAME_DEVICE_INCLUDE_USER_VERIFICATION_CONFIG,
                Boolean.toString(includeUserVerification)));
        Mockito.when(context.getAuthenticatorConfig()).thenReturn(config);
        Mockito.when(context.getSession()).thenReturn(session);
        Mockito.when(context.getRealm()).thenReturn(realm);
        UriInfo uriInfo = Mockito.mock(UriInfo.class);
        Mockito.when(uriInfo.getBaseUri()).thenReturn(baseUri);
        Mockito.when(context.getUriInfo()).thenReturn(uriInfo);
        return context;
    }

    private PushChallenge buildChallenge(String userVerificationValue) {
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
                userVerificationValue,
                List.of());
    }

    private PushCredentialData credentialData(String credentialId) {
        return new PushCredentialData(null, 0L, null, null, null, credentialId, null);
    }

    private KeyWrapper buildKeyWrapper(String kid, String algorithm) throws Exception {
        KeyPair pair = generateRsaKeyPair();
        KeyWrapper wrapper = new KeyWrapper();
        wrapper.setKid(kid);
        wrapper.setAlgorithm(algorithm);
        wrapper.setPrivateKey(pair.getPrivate());
        wrapper.setPublicKey(pair.getPublic());
        return wrapper;
    }

    private KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
