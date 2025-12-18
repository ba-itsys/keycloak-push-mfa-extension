package de.arbeitsagentur.keycloak.push;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.push.support.AdminClient;
import de.arbeitsagentur.keycloak.push.support.BrowserSession;
import de.arbeitsagentur.keycloak.push.support.ContainerLogWatcher;
import de.arbeitsagentur.keycloak.push.support.DeviceClient;
import de.arbeitsagentur.keycloak.push.support.DeviceKeyType;
import de.arbeitsagentur.keycloak.push.support.DeviceSigningKey;
import de.arbeitsagentur.keycloak.push.support.DeviceState;
import de.arbeitsagentur.keycloak.push.support.HtmlPage;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

@Testcontainers
@ExtendWith(ContainerLogWatcher.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PushMfaIntegrationIT {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path EXTENSION_JAR = locateProviderJar();
    private static final Path REALM_FILE =
            Paths.get("config", "demo-realm.json").toAbsolutePath();
    private static final String TEST_USERNAME = "test";
    private static final String TEST_PASSWORD = "test";
    private static final String ATTACKER_USERNAME = "attacker";
    private static final String ATTACKER_PASSWORD = "attacker";

    @Container
    private static final GenericContainer<?> KEYCLOAK = new GenericContainer<>("quay.io/keycloak/keycloak:26.4.5")
            .withExposedPorts(8080)
            .withCopyFileToContainer(
                    MountableFile.forHostPath(EXTENSION_JAR), "/opt/keycloak/providers/keycloak-push-mfa.jar")
            .withCopyFileToContainer(MountableFile.forHostPath(REALM_FILE), "/opt/keycloak/data/import/demo-realm.json")
            .withEnv("KEYCLOAK_ADMIN", "admin")
            .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
            .withCommand(
                    "start-dev --hostname=localhost --hostname-strict=false --http-enabled=true --import-realm --features=dpop")
            .waitingFor(Wait.forHttp("/realms/master").forStatusCode(200))
            .withStartupTimeout(Duration.ofMinutes(3));

    private URI baseUri;
    private AdminClient adminClient;

    @BeforeAll
    void setup() {
        baseUri = URI.create(String.format("http://%s:%d/", KEYCLOAK.getHost(), KEYCLOAK.getMappedPort(8080)));
        adminClient = new AdminClient(baseUri);
    }

    @BeforeEach
    void resetUserVerificationConfig() throws Exception {
        adminClient.configurePushMfaUserVerification(
                PushMfaConstants.USER_VERIFICATION_NONE, PushMfaConstants.DEFAULT_USER_VERIFICATION_PIN_LENGTH);
    }

    @Test
    void deviceEnrollsAndApprovesLogin() throws Exception {
        DeviceClient deviceClient = enrollDevice();
        completeLoginFlow(deviceClient);
    }

    @Test
    void ecdsaDeviceEnrollsAndApprovesLogin() throws Exception {
        DeviceClient deviceClient = enrollDevice(DeviceKeyType.ECDSA);
        completeLoginFlow(deviceClient);
    }

    @Test
    void deviceDeniesLoginChallenge() throws Exception {
        DeviceClient deviceClient = enrollDevice();
        BrowserSession pushSession = new BrowserSession(baseUri);
        HtmlPage pushLogin = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(pushLogin, TEST_USERNAME, TEST_PASSWORD);
        BrowserSession.DeviceChallenge confirm = pushSession.extractDeviceChallenge(waitingPage);

        String status = deviceClient.respondToChallenge(
                confirm.confirmToken(), confirm.challengeId(), PushMfaConstants.CHALLENGE_DENY);
        assertEquals("denied", status);

        HtmlPage deniedPage = pushSession.submitPushChallengeForPage(confirm.formAction());
        String pageText = deniedPage.document().text().toLowerCase();
        assertTrue(
                pageText.contains("push approval denied") || pageText.contains("push request was denied"),
                "Denied page should explain the rejected push login");
    }

    @Test
    void userVerificationNoneDoesNotRequireClaim() throws Exception {
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_NONE);
        DeviceClient deviceClient = enrollDevice();
        BrowserSession pushSession = new BrowserSession(baseUri);

        HtmlPage pushLogin = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(pushLogin, TEST_USERNAME, TEST_PASSWORD);
        assertNull(pushSession.extractUserVerification(waitingPage));
        BrowserSession.DeviceChallenge confirm = pushSession.extractDeviceChallenge(waitingPage);

        String status = deviceClient.respondToChallenge(
                confirm.confirmToken(), confirm.challengeId(), PushMfaConstants.CHALLENGE_APPROVE);
        assertEquals("approved", status);
        pushSession.completePushChallenge(confirm.formAction());
    }

    @Test
    void numberMatchRequiresCorrectSelection() throws Exception {
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_NUMBER_MATCH);
        DeviceClient deviceClient = enrollDevice();
        BrowserSession pushSession = new BrowserSession(baseUri);

        HtmlPage pushLogin = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(pushLogin, TEST_USERNAME, TEST_PASSWORD);
        BrowserSession.DeviceChallenge confirm = pushSession.extractDeviceChallenge(waitingPage);

        String displayed = pushSession.extractUserVerification(waitingPage);
        assertNotNull(displayed);
        assertTrue(
                displayed.matches("^(0|[1-9][0-9]?)$"), () -> "Expected number-match value 0-99 but got: " + displayed);

        SignedJWT confirmToken = SignedJWT.parse(confirm.confirmToken());
        JWTClaimsSet confirmClaims = confirmToken.getJWTClaimsSet();
        assertNull(confirmClaims.getClaim("userVerification"));
        assertNull(confirmClaims.getClaim("number"));

        JsonNode pending = deviceClient.fetchPendingChallenges();
        JsonNode challenge = pending.get(0);
        assertEquals(confirm.challengeId(), challenge.path("cid").asText());
        JsonNode verification = challenge.path("userVerification");
        assertEquals(
                PushMfaConstants.USER_VERIFICATION_NUMBER_MATCH,
                verification.path("type").asText());
        verification
                .fieldNames()
                .forEachRemaining(field -> assertTrue(
                        Set.of("type", "numbers", "pinLength").contains(field),
                        () -> "Unexpected userVerification field: " + field + " in " + verification));
        assertTrue(
                verification.path("pinLength").isMissingNode()
                        || verification.path("pinLength").isNull(),
                () -> "number-match should not include pinLength: " + verification);
        JsonNode numbers = verification.path("numbers");
        assertTrue(numbers.isArray(), () -> "Expected numbers array but got: " + verification);
        assertEquals(3, numbers.size(), () -> "Expected 3 options but got: " + numbers);

        Set<String> uniqueOptions = new HashSet<>();
        String wrong = null;
        boolean containsDisplayed = false;
        for (JsonNode option : numbers) {
            String value = option.asText();
            assertTrue(value.matches("^(0|[1-9][0-9]?)$"), () -> "Expected number-match option 0-99 but got: " + value);
            uniqueOptions.add(value);
            if (displayed.equals(value)) {
                containsDisplayed = true;
                continue;
            }
            if (wrong == null) {
                wrong = value;
            }
        }
        assertEquals(3, uniqueOptions.size(), () -> "Expected unique options but got: " + numbers);
        assertTrue(containsDisplayed, "Displayed number must be one of the device options");
        assertNotNull(wrong);

        HttpResponse<String> rejected = deviceClient.respondToChallengeRaw(
                confirm.confirmToken(), confirm.challengeId(), PushMfaConstants.CHALLENGE_APPROVE, wrong);
        assertEquals(403, rejected.statusCode(), () -> "Expected mismatch rejection but got: " + rejected.body());

        String approved = deviceClient.respondToChallenge(
                confirm.confirmToken(), confirm.challengeId(), PushMfaConstants.CHALLENGE_APPROVE, displayed);
        assertEquals("approved", approved);
        pushSession.completePushChallenge(confirm.formAction());
    }

    @Test
    void numberMatchCorrectPositionIsApproximatelyUniform() throws Exception {
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_NUMBER_MATCH);
        DeviceClient deviceClient = enrollDevice();

        int samples = 150;
        int[] counts = new int[3];
        for (int attempt = 0; attempt < samples; attempt++) {
            BrowserSession pushSession = new BrowserSession(baseUri);
            HtmlPage pushLogin = pushSession.startAuthorization("test-app");
            HtmlPage waitingPage = pushSession.submitLogin(pushLogin, TEST_USERNAME, TEST_PASSWORD);
            BrowserSession.DeviceChallenge confirm = pushSession.extractDeviceChallenge(waitingPage);

            String displayed = pushSession.extractUserVerification(waitingPage);
            assertNotNull(displayed);
            assertTrue(
                    displayed.matches("^(0|[1-9][0-9]?)$"),
                    () -> "Expected number-match value 0-99 but got: " + displayed);

            JsonNode pending = deviceClient.fetchPendingChallenges();
            JsonNode matching = null;
            for (JsonNode candidate : pending) {
                if (confirm.challengeId().equals(candidate.path("cid").asText())) {
                    matching = candidate;
                    break;
                }
            }
            assertNotNull(matching, () -> "Pending response did not contain " + confirm.challengeId() + ": " + pending);

            JsonNode numbers = matching.path("userVerification").path("numbers");
            assertTrue(numbers.isArray(), "Expected numbers array but got: " + matching);
            assertEquals(3, numbers.size(), () -> "Expected 3 number-match options but got: " + numbers);
            int index = -1;
            for (int i = 0; i < numbers.size(); i++) {
                if (displayed.equals(numbers.get(i).asText())) {
                    index = i;
                    break;
                }
            }
            assertTrue(index >= 0, () -> "Displayed number not found in pending: " + displayed + " vs " + numbers);
            counts[index]++;

            String status = deviceClient.respondToChallenge(
                    confirm.confirmToken(), confirm.challengeId(), PushMfaConstants.CHALLENGE_DENY);
            assertEquals("denied", status);
            pushSession.submitPushChallengeForPage(confirm.formAction());
        }

        // Regression test for randomness:
        // In number-match mode the browser shows 1 of the 3 numbers that the device receives via /login/pending.
        // The shown number should be equally likely to be in position 0, 1, or 2 of that 3-item list. If it keeps
        // landing in the same position (or strongly prefers one position), that's a bug.
        //
        // We create many challenges, count which position the shown number had, and then run a simple "are these
        // three counts roughly equal?" check (a chi-square goodness-of-fit test for 3 buckets).
        // Reference: https://en.wikipedia.org/wiki/Chi-squared_test
        // Why 18.42? With 3 buckets the test has df=2; 18.42 is the 99.99th percentile (p=0.0001), so a truly uniform
        // implementation almost never fails this test by chance, but biased placement still gets caught.
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
    void numberMatchDenyWorksWithoutSelection() throws Exception {
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_NUMBER_MATCH);
        DeviceClient deviceClient = enrollDevice();
        BrowserSession pushSession = new BrowserSession(baseUri);

        HtmlPage pushLogin = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(pushLogin, TEST_USERNAME, TEST_PASSWORD);
        BrowserSession.DeviceChallenge confirm = pushSession.extractDeviceChallenge(waitingPage);

        String status = deviceClient.respondToChallenge(
                confirm.confirmToken(), confirm.challengeId(), PushMfaConstants.CHALLENGE_DENY);
        assertEquals("denied", status);

        HtmlPage deniedPage = pushSession.submitPushChallengeForPage(confirm.formAction());
        String pageText = deniedPage.document().text().toLowerCase();
        assertTrue(
                pageText.contains("push approval denied") || pageText.contains("push request was denied"),
                "Denied page should explain the rejected push login");
    }

    @Test
    void pinRequiresCorrectPin() throws Exception {
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_PIN);
        DeviceClient deviceClient = enrollDevice();
        BrowserSession pushSession = new BrowserSession(baseUri);

        HtmlPage pushLogin = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(pushLogin, TEST_USERNAME, TEST_PASSWORD);
        BrowserSession.DeviceChallenge confirm = pushSession.extractDeviceChallenge(waitingPage);

        String pin = pushSession.extractUserVerification(waitingPage);
        assertNotNull(pin);
        assertTrue(pin.matches("\\d{4}"), () -> "Expected 4-digit pin but got: " + pin);

        SignedJWT confirmToken = SignedJWT.parse(confirm.confirmToken());
        JWTClaimsSet confirmClaims = confirmToken.getJWTClaimsSet();
        assertNull(confirmClaims.getClaim("userVerification"));
        assertNull(confirmClaims.getClaim("pin"));

        JsonNode pending = deviceClient.fetchPendingChallenges();
        JsonNode challenge = pending.get(0);
        assertEquals(confirm.challengeId(), challenge.path("cid").asText());
        JsonNode verification = challenge.path("userVerification");
        assertEquals(
                PushMfaConstants.USER_VERIFICATION_PIN,
                verification.path("type").asText());
        assertEquals(4, verification.path("pinLength").asInt());
        verification
                .fieldNames()
                .forEachRemaining(field -> assertTrue(
                        Set.of("type", "numbers", "pinLength").contains(field),
                        () -> "Unexpected userVerification field: " + field + " in " + verification));
        assertTrue(
                verification.path("numbers").isMissingNode()
                        || verification.path("numbers").isNull(),
                () -> "Pin verification should not include numbers: " + verification);

        HttpResponse<String> missingVerification = deviceClient.respondToChallengeRaw(
                confirm.confirmToken(), confirm.challengeId(), PushMfaConstants.CHALLENGE_APPROVE);
        assertEquals(
                400,
                missingVerification.statusCode(),
                () -> "Expected missing verification rejection but got: " + missingVerification.body());
        assertEquals(
                "Missing user verification",
                MAPPER.readTree(missingVerification.body()).path("error").asText(),
                () -> "Unexpected missing verification error body: " + missingVerification.body());

        String wrong = "0000".equals(pin) ? "0001" : "0000";
        HttpResponse<String> rejected = deviceClient.respondToChallengeRaw(
                confirm.confirmToken(), confirm.challengeId(), PushMfaConstants.CHALLENGE_APPROVE, wrong);
        assertEquals(403, rejected.statusCode(), () -> "Expected mismatch rejection but got: " + rejected.body());

        String approved = deviceClient.respondToChallenge(
                confirm.confirmToken(), confirm.challengeId(), PushMfaConstants.CHALLENGE_APPROVE, pin);
        assertEquals("approved", approved);
        pushSession.completePushChallenge(confirm.formAction());
    }

    @Test
    void pinMustBeSentWithLeadingZeros() throws Exception {
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_PIN);
        DeviceClient deviceClient = enrollDevice();
        BrowserSession pushSession = new BrowserSession(baseUri);

        HtmlPage pushLogin = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(pushLogin, TEST_USERNAME, TEST_PASSWORD);
        BrowserSession.DeviceChallenge confirm = pushSession.extractDeviceChallenge(waitingPage);

        String pin = pushSession.extractUserVerification(waitingPage);
        assertNotNull(pin);
        assertTrue(pin.matches("\\d{4}"), "Expected 4-digit pin but got: " + pin);

        int refreshes = 0;
        while (!pin.startsWith("0") && refreshes < 100) {
            waitingPage = pushSession.refreshPushChallenge(waitingPage);
            confirm = pushSession.extractDeviceChallenge(waitingPage);
            pin = pushSession.extractUserVerification(waitingPage);
            assertNotNull(pin);
            assertTrue(pin.matches("\\d{4}"), "Expected 4-digit pin but got: " + pin);
            refreshes++;
        }
        assertTrue(
                pin.startsWith("0"),
                "Expected a PIN with leading zero after " + refreshes + " refreshes but got: " + pin);

        String withoutLeadingZeros = pin.replaceFirst("^0+", "");
        if (withoutLeadingZeros.isEmpty()) {
            withoutLeadingZeros = "0";
        }

        HttpResponse<String> rejected = deviceClient.respondToChallengeRaw(
                confirm.confirmToken(), confirm.challengeId(), PushMfaConstants.CHALLENGE_APPROVE, withoutLeadingZeros);
        assertEquals(403, rejected.statusCode(), () -> "Expected trimmed PIN rejection but got: " + rejected.body());
        assertEquals(
                "User verification mismatch",
                MAPPER.readTree(rejected.body()).path("error").asText(),
                () -> "Unexpected error body: " + rejected.body());

        String approved = deviceClient.respondToChallenge(
                confirm.confirmToken(), confirm.challengeId(), PushMfaConstants.CHALLENGE_APPROVE, pin);
        assertEquals("approved", approved);
        pushSession.completePushChallenge(confirm.formAction());
    }

    @Test
    void pinLengthIsConfigurable() throws Exception {
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_PIN, 6);
        DeviceClient deviceClient = enrollDevice();
        BrowserSession pushSession = new BrowserSession(baseUri);

        HtmlPage pushLogin = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(pushLogin, TEST_USERNAME, TEST_PASSWORD);
        BrowserSession.DeviceChallenge confirm = pushSession.extractDeviceChallenge(waitingPage);

        String pin = pushSession.extractUserVerification(waitingPage);
        assertNotNull(pin);
        assertTrue(pin.matches("\\d{6}"), () -> "Expected 6-digit pin but got: " + pin);

        JsonNode pending = deviceClient.fetchPendingChallenges();
        JsonNode challenge = pending.get(0);
        assertEquals(confirm.challengeId(), challenge.path("cid").asText());
        JsonNode verification = challenge.path("userVerification");
        assertEquals(
                PushMfaConstants.USER_VERIFICATION_PIN,
                verification.path("type").asText());
        assertEquals(6, verification.path("pinLength").asInt());

        String wrong = "0".repeat(6);
        if (wrong.equals(pin)) {
            wrong = "0".repeat(5) + "1";
        }
        HttpResponse<String> rejected = deviceClient.respondToChallengeRaw(
                confirm.confirmToken(), confirm.challengeId(), PushMfaConstants.CHALLENGE_APPROVE, wrong);
        assertEquals(403, rejected.statusCode(), () -> "Expected mismatch rejection but got: " + rejected.body());

        String approved = deviceClient.respondToChallenge(
                confirm.confirmToken(), confirm.challengeId(), PushMfaConstants.CHALLENGE_APPROVE, pin);
        assertEquals("approved", approved);
        pushSession.completePushChallenge(confirm.formAction());
    }

    @Test
    void pinDenyWorksWithoutPin() throws Exception {
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_PIN);
        DeviceClient deviceClient = enrollDevice();
        BrowserSession pushSession = new BrowserSession(baseUri);

        HtmlPage pushLogin = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(pushLogin, TEST_USERNAME, TEST_PASSWORD);
        BrowserSession.DeviceChallenge confirm = pushSession.extractDeviceChallenge(waitingPage);

        String status = deviceClient.respondToChallenge(
                confirm.confirmToken(), confirm.challengeId(), PushMfaConstants.CHALLENGE_DENY);
        assertEquals("denied", status);

        HtmlPage deniedPage = pushSession.submitPushChallengeForPage(confirm.formAction());
        String pageText = deniedPage.document().text().toLowerCase();
        assertTrue(
                pageText.contains("push approval denied") || pageText.contains("push request was denied"),
                "Denied page should explain the rejected push login");
    }

    @Test
    void userRefreshesEnrollmentChallengeAndEnrolls() throws Exception {
        adminClient.resetUserState(TEST_USERNAME);
        DeviceState deviceState = DeviceState.create(DeviceKeyType.RSA);
        DeviceClient deviceClient = new DeviceClient(baseUri, deviceState);

        BrowserSession enrollmentSession = new BrowserSession(baseUri);
        HtmlPage loginPage = enrollmentSession.startAuthorization("test-app");
        HtmlPage enrollmentPage = enrollmentSession.submitLogin(loginPage, TEST_USERNAME, TEST_PASSWORD);
        String originalToken = enrollmentSession.extractEnrollmentToken(enrollmentPage);
        String originalChallenge = enrollmentSession.extractEnrollmentChallengeId(enrollmentPage);

        HtmlPage refreshedPage = enrollmentSession.refreshEnrollmentChallenge(enrollmentPage);
        String refreshedToken = enrollmentSession.extractEnrollmentToken(refreshedPage);
        String refreshedChallenge = enrollmentSession.extractEnrollmentChallengeId(refreshedPage);

        assertNotEquals(originalToken, refreshedToken, "Refresh should issue a new enrollment token");
        assertNotEquals(originalChallenge, refreshedChallenge, "Refresh should create a new enrollment challenge");

        deviceClient.completeEnrollment(refreshedToken);
        enrollmentSession.submitEnrollmentCheck(refreshedPage);
        completeLoginFlow(deviceClient);
    }

    @Test
    void userRefreshesLoginChallengeAndAuthenticates() throws Exception {
        DeviceClient deviceClient = enrollDevice();
        BrowserSession pushSession = new BrowserSession(baseUri);

        HtmlPage loginPage = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(loginPage, TEST_USERNAME, TEST_PASSWORD);
        BrowserSession.DeviceChallenge initialChallenge = pushSession.extractDeviceChallenge(waitingPage);

        HtmlPage refreshedWaiting = pushSession.refreshPushChallenge(waitingPage);
        BrowserSession.DeviceChallenge refreshedChallenge = pushSession.extractDeviceChallenge(refreshedWaiting);

        assertNotEquals(
                initialChallenge.challengeId(),
                refreshedChallenge.challengeId(),
                "Refreshing should rotate the pending challenge");

        String status = deviceClient.respondToChallenge(
                refreshedChallenge.confirmToken(),
                refreshedChallenge.challengeId(),
                PushMfaConstants.CHALLENGE_APPROVE);
        assertEquals("approved", status);
        try {
            pushSession.completePushChallenge(refreshedChallenge.formAction());
        } catch (AssertionError | IllegalStateException ignored) {
            // The refreshed browser request may already be past the login step; it's enough that the challenge was
            // approved and no error was returned.
        }
    }

    @Test
    void refreshCreatesNewChallengeForSameSession() throws Exception {
        DeviceClient deviceClient = enrollDevice();
        BrowserSession pushSession = new BrowserSession(baseUri);

        HtmlPage firstLogin = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(firstLogin, TEST_USERNAME, TEST_PASSWORD);
        BrowserSession.DeviceChallenge firstChallenge = pushSession.extractDeviceChallenge(waitingPage);
        JWTClaimsSet firstClaims =
                SignedJWT.parse(firstChallenge.confirmToken()).getJWTClaimsSet();

        HtmlPage refreshed = pushSession.refreshPushChallenge(waitingPage);
        BrowserSession.DeviceChallenge refreshedChallenge = pushSession.extractDeviceChallenge(refreshed);
        JWTClaimsSet refreshedClaims =
                SignedJWT.parse(refreshedChallenge.confirmToken()).getJWTClaimsSet();
        JsonNode pending = deviceClient.fetchPendingChallenges();
        long pendingExpires = pending.get(0).path("expiresAt").asLong();
        String pendingCid = pending.get(0).path("cid").asText();
        assertEquals(TEST_USERNAME, pending.get(0).path("username").asText());
        assertEquals(refreshedChallenge.challengeId(), pendingCid);

        assertNotEquals(
                firstChallenge.challengeId(),
                refreshedChallenge.challengeId(),
                "Challenge should rotate for the same session");
        assertNotEquals(firstChallenge.confirmToken(), refreshedChallenge.confirmToken());
        long refreshedTtlSeconds =
                refreshedClaims.getExpirationTime().toInstant().getEpochSecond()
                        - refreshedClaims.getIssueTime().toInstant().getEpochSecond();
        assertTrue(
                refreshedTtlSeconds >= 100 && refreshedTtlSeconds <= 140,
                "Refreshed challenge should use the standard TTL");
        assertEquals(
                refreshedClaims.getExpirationTime().toInstant().getEpochSecond(),
                pendingExpires,
                "Pending challenge expiry should align with the refreshed challenge");

        deviceClient.respondToChallenge(
                refreshedChallenge.confirmToken(),
                refreshedChallenge.challengeId(),
                PushMfaConstants.CHALLENGE_APPROVE);
        pushSession.completePushChallenge(refreshedChallenge.formAction());
    }

    @Test
    void refreshInvalidatesOldChallenge() throws Exception {
        DeviceClient deviceClient = enrollDevice();
        BrowserSession pushSession = new BrowserSession(baseUri);

        HtmlPage loginPage = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(loginPage, TEST_USERNAME, TEST_PASSWORD);
        BrowserSession.DeviceChallenge firstChallenge = pushSession.extractDeviceChallenge(waitingPage);

        HtmlPage refreshedPage = pushSession.refreshPushChallenge(waitingPage);
        BrowserSession.DeviceChallenge refreshedChallenge = pushSession.extractDeviceChallenge(refreshedPage);

        var staleResponse = deviceClient.respondToChallengeRaw(
                firstChallenge.confirmToken(), firstChallenge.challengeId(), PushMfaConstants.CHALLENGE_APPROVE);
        assertEquals(404, staleResponse.statusCode(), "Stale challenge should not be accepted");

        deviceClient.respondToChallenge(
                refreshedChallenge.confirmToken(),
                refreshedChallenge.challengeId(),
                PushMfaConstants.CHALLENGE_APPROVE);
        pushSession.completePushChallenge(refreshedChallenge.formAction());
    }

    @Test
    void pendingChallengeBlocksOtherSession() throws Exception {
        DeviceClient deviceClient = enrollDevice();
        BrowserSession firstSession = new BrowserSession(baseUri);

        HtmlPage loginPage = firstSession.startAuthorization("test-app");
        HtmlPage waitingPage = firstSession.submitLogin(loginPage, TEST_USERNAME, TEST_PASSWORD);
        BrowserSession.DeviceChallenge firstChallenge = firstSession.extractDeviceChallenge(waitingPage);

        BrowserSession secondSession = new BrowserSession(baseUri);
        HtmlPage secondLogin = secondSession.startAuthorization("test-app");
        IllegalStateException error = assertThrows(
                IllegalStateException.class,
                () -> secondSession.submitLogin(secondLogin, TEST_USERNAME, TEST_PASSWORD),
                "Second session should be blocked while a challenge is pending");
        String message = error.getMessage().toLowerCase();
        assertTrue(
                message.contains("pending push approval")
                        || message.contains("too many requests")
                        || message.contains("429"),
                "Error message should mention the pending approval");

        deviceClient.respondToChallenge(
                firstChallenge.confirmToken(), firstChallenge.challengeId(), PushMfaConstants.CHALLENGE_DENY);
    }

    @Test
    void deviceRotatesKeyAndAuthenticates() throws Exception {
        DeviceClient deviceClient = enrollDevice();
        DeviceSigningKey rotatedKey = DeviceSigningKey.generateRsa();
        String status = deviceClient.rotateDeviceKey(rotatedKey);
        assertEquals("rotated", status);

        JsonNode credentialData =
                adminClient.fetchPushCredential(deviceClient.state().userId());
        JsonNode storedKey = MAPPER.readTree(credentialData.path("publicKeyJwk").asText());
        assertEquals(MAPPER.readTree(rotatedKey.publicJwk().toJSONString()), storedKey);

        completeLoginFlow(deviceClient);
    }

    @Test
    void deviceUpdatesPushProvider() throws Exception {
        DeviceClient deviceClient = enrollDevice();
        String newProviderId = "integration-provider-" + UUID.randomUUID();
        String newProviderType = "log-updated";
        String status = deviceClient.updatePushProvider(newProviderId, newProviderType);
        assertEquals("updated", status);

        JsonNode credentialData =
                adminClient.fetchPushCredential(deviceClient.state().userId());
        assertEquals(newProviderId, credentialData.path("pushProviderId").asText());
        assertEquals(newProviderType, credentialData.path("pushProviderType").asText());

        String secondStatus = deviceClient.updatePushProvider(newProviderId, newProviderType);
        assertEquals("unchanged", secondStatus);
    }

    private void completeLoginFlow(DeviceClient deviceClient) throws Exception {
        BrowserSession pushSession = new BrowserSession(baseUri);
        HtmlPage pushLogin = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(pushLogin, TEST_USERNAME, TEST_PASSWORD);
        BrowserSession.DeviceChallenge confirm = pushSession.extractDeviceChallenge(waitingPage);
        deviceClient.respondToChallenge(confirm.confirmToken(), confirm.challengeId());
        pushSession.completePushChallenge(confirm.formAction());
    }

    @Test
    void injectedChallengeIdCannotBypassMfa() throws Exception {
        try {
            adminClient.ensureUser(ATTACKER_USERNAME, ATTACKER_PASSWORD);
            DeviceClient victimDevice = enrollDevice(TEST_USERNAME, TEST_PASSWORD, DeviceKeyType.RSA);
            DeviceClient attackerDevice = enrollDevice(ATTACKER_USERNAME, ATTACKER_PASSWORD, DeviceKeyType.RSA);

            BrowserSession attackerSession = new BrowserSession(baseUri);
            HtmlPage attackerLogin = attackerSession.startAuthorization("test-app");
            HtmlPage attackerWaiting = attackerSession.submitLogin(attackerLogin, ATTACKER_USERNAME, ATTACKER_PASSWORD);
            BrowserSession.DeviceChallenge attackerChallenge = attackerSession.extractDeviceChallenge(attackerWaiting);
            attackerDevice.respondToChallenge(attackerChallenge.confirmToken(), attackerChallenge.challengeId());

            BrowserSession victimSession = new BrowserSession(baseUri);
            HtmlPage victimLogin = victimSession.startAuthorization("test-app");
            BrowserSession.PageOrRedirect victimResult = victimSession.submitLoginResult(
                    victimLogin, TEST_USERNAME, TEST_PASSWORD, Map.of("challengeId", attackerChallenge.challengeId()));
            assertNotNull(victimResult.page(), "Victim login should not bypass push MFA");

            BrowserSession.DeviceChallenge victimChallenge = victimSession.extractDeviceChallenge(victimResult.page());
            assertNotEquals(attackerChallenge.challengeId(), victimChallenge.challengeId());

            victimDevice.respondToChallenge(victimChallenge.confirmToken(), victimChallenge.challengeId());
            victimSession.completePushChallenge(victimChallenge.formAction());

            attackerSession.completePushChallenge(attackerChallenge.formAction());
        } catch (Exception ex) {
            System.err.println("Keycloak container logs:\n" + KEYCLOAK.getLogs());
            throw ex;
        }
    }

    @Test
    void dpopReplayIsRejected() throws Exception {
        try {
            DeviceClient deviceClient = enrollDevice();
            HttpClient httpClient =
                    HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
            String encodedUserId = URLEncoder.encode(deviceClient.state().userId(), StandardCharsets.UTF_8);
            URI pendingUri = baseUri.resolve("/realms/demo/push-mfa/login/pending?userId=" + encodedUserId);
            String proof = deviceClient.createDpopProof(
                    "GET", pendingUri, UUID.randomUUID().toString());

            HttpRequest request = HttpRequest.newBuilder(pendingUri)
                    .header("Authorization", "DPoP " + deviceClient.accessToken())
                    .header("DPoP", proof)
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> first = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, first.statusCode(), () -> "First request failed: " + first.body());

            HttpResponse<String> second = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(403, second.statusCode(), () -> "Replay should be rejected: " + second.body());
        } catch (Exception ex) {
            System.err.println("Keycloak container logs:\n" + KEYCLOAK.getLogs());
            throw ex;
        }
    }

    private DeviceClient enrollDevice() throws Exception {
        return enrollDevice(DeviceKeyType.RSA);
    }

    private DeviceClient enrollDevice(DeviceKeyType keyType) throws Exception {
        return enrollDevice(TEST_USERNAME, TEST_PASSWORD, keyType);
    }

    private DeviceClient enrollDevice(String username, String password, DeviceKeyType keyType) throws Exception {
        adminClient.resetUserState(username);
        DeviceState deviceState = DeviceState.create(keyType);
        DeviceClient deviceClient = new DeviceClient(baseUri, deviceState);

        BrowserSession enrollmentSession = new BrowserSession(baseUri);
        HtmlPage loginPage = enrollmentSession.startAuthorization("test-app");
        HtmlPage enrollmentPage = enrollmentSession.submitLogin(loginPage, username, password);
        String enrollmentToken = enrollmentSession.extractEnrollmentToken(enrollmentPage);
        deviceClient.completeEnrollment(enrollmentToken);
        enrollmentSession.submitEnrollmentCheck(enrollmentPage);
        return deviceClient;
    }

    /**
     * find the versioned JAR produced by Maven, e.g. keycloak-push-mfa-extension.jar
     */
    private static Path locateProviderJar() {
        Path targetDir = Paths.get("target");
        if (!Files.isDirectory(targetDir)) {
            throw new IllegalStateException("target directory not found. Run mvn package before integration tests.");
        }
        Path candidate = targetDir.resolve("keycloak-push-mfa-extension.jar");
        if (Files.isRegularFile(candidate)) {
            return candidate;
        }
        throw new IllegalStateException(
                "Provider JAR not found at " + candidate + ". Run mvn package before integration tests.");
    }
}
