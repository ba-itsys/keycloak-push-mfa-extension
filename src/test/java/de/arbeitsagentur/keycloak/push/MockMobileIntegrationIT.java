package de.arbeitsagentur.keycloak.push;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.push.support.AdminClient;
import de.arbeitsagentur.keycloak.push.support.BrowserSession;
import de.arbeitsagentur.keycloak.push.support.ContainerLogWatcher;
import de.arbeitsagentur.keycloak.push.support.HtmlPage;
import de.arbeitsagentur.keycloak.push.support.MockMobileClient;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

@Testcontainers
@ExtendWith(ContainerLogWatcher.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MockMobileIntegrationIT {

    private static final Path EXTENSION_JAR = locateProviderJar();
    private static final Path REALM_FILE =
            Paths.get("config", "demo-realm.json").toAbsolutePath();
    private static final Path MOCK_APP_DIR = Paths.get("mock", "mobile").toAbsolutePath();
    private static final String TEST_USERNAME = "test";
    private static final Network NETWORK = Network.newNetwork();

    @Container
    private static final GenericContainer<?> KEYCLOAK = new GenericContainer<>("quay.io/keycloak/keycloak:26.4.5")
            .withNetwork(NETWORK)
            .withNetworkAliases("keycloak")
            .withExposedPorts(8080)
            .withCopyFileToContainer(
                    MountableFile.forHostPath(EXTENSION_JAR), "/opt/keycloak/providers/keycloak-push-mfa.jar")
            .withCopyFileToContainer(MountableFile.forHostPath(REALM_FILE), "/opt/keycloak/data/import/demo-realm.json")
            .withEnv("KEYCLOAK_ADMIN", "admin")
            .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
            .withCommand(
                    "start-dev --hostname=localhost --hostname-strict=false --http-enabled=true --import-realm --features=dpop")
            .waitingFor(Wait.forHttp("/realms/master").forStatusCode(200))
            .withStartupTimeout(Duration.ofMinutes(4));

    @Container
    private static final GenericContainer<?> MOBILE = new GenericContainer<>("node:24-bullseye")
            .withNetwork(NETWORK)
            .withExposedPorts(3001)
            .withCopyFileToContainer(MountableFile.forHostPath(MOCK_APP_DIR), "/app")
            .withEnv("REALM_BASE", "http://keycloak:8080/realms/demo")
            .withEnv("ENROLL_COMPLETE_URL", "http://keycloak:8080/realms/demo/push-mfa/enroll/complete")
            .withEnv("TOKEN_ENDPOINT", "http://keycloak:8080/realms/demo/protocol/openid-connect/token")
            .withEnv("CHALLENGE_URL", "http://keycloak:8080/realms/demo/push-mfa/login/challenges/CHALLENGE_ID/respond")
            .withEnv("PORT", "3001")
            .withCommand("sh", "-c", "cd /app && npm ci --no-progress && npm run build && npm run start")
            .waitingFor(Wait.forHttp("/meta").forStatusCode(200).forPort(3001))
            .withStartupTimeout(Duration.ofMinutes(6));

    private URI baseUri;
    private MockMobileClient mockMobileClient;
    private AdminClient adminClient;

    @BeforeAll
    void setup() {
        baseUri = URI.create(String.format("http://%s:%d/", KEYCLOAK.getHost(), KEYCLOAK.getMappedPort(8080)));
        adminClient = new AdminClient(baseUri);
        mockMobileClient = new MockMobileClient(
                URI.create(String.format("http://%s:%d", MOBILE.getHost(), MOBILE.getMappedPort(3001))));
    }

    @Test
    void mockEnrollsDeviceSuccessfully() throws Exception {
        adminClient.resetUserState(TEST_USERNAME);
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_NONE);
        EnrollmentFlow enrollment = startEnrollmentFlow();

        MockMobileClient.Response response = mockMobileClient.enroll(enrollment.enrollmentToken());
        assertEquals(200, response.httpStatus(), () -> describe(response));
        assertEquals(200, response.responseStatus(), () -> describe(response));

        enrollment.session().submitEnrollmentCheck(enrollment.enrollmentPage());

        String userId = subjectFromToken(enrollment.enrollmentToken());
        JsonNode credential = adminClient.fetchPushCredential(userId);
        assertEquals(
                "demo-push-provider-token", credential.path("pushProviderId").asText());
        assertEquals("log", credential.path("pushProviderType").asText());
        assertEquals("-device-alias-" + userId, credential.path("credentialId").asText());
    }

    @Test
    void mockApprovesLoginChallenge() throws Exception {
        adminClient.resetUserState(TEST_USERNAME);
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_NONE);
        enrollWithMockDevice();

        BrowserSession pushSession = new BrowserSession(baseUri);
        HtmlPage loginPage = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(loginPage, TEST_USERNAME, TEST_USERNAME);
        BrowserSession.DeviceChallenge challenge = pushSession.extractDeviceChallenge(waitingPage);

        MockMobileClient.Response approval = mockMobileClient.approveLogin(challenge.confirmToken());
        assertEquals(200, approval.httpStatus(), () -> describe(approval));
        assertEquals(200, approval.responseStatus(), () -> describe(approval));

        pushSession.completePushChallenge(challenge.formAction());
    }

    @Test
    void mockHandlesRefreshedChallenge() throws Exception {
        adminClient.resetUserState(TEST_USERNAME);
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_NONE);
        enrollWithMockDevice();

        BrowserSession pushSession = new BrowserSession(baseUri);
        HtmlPage loginPage = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(loginPage, TEST_USERNAME, TEST_USERNAME);
        BrowserSession.DeviceChallenge firstChallenge = pushSession.extractDeviceChallenge(waitingPage);

        HtmlPage refreshedPage = pushSession.refreshPushChallenge(waitingPage);
        BrowserSession.DeviceChallenge refreshedChallenge = pushSession.extractDeviceChallenge(refreshedPage);
        assertNotEquals(
                firstChallenge.challengeId(),
                refreshedChallenge.challengeId(),
                "Refreshing should rotate the pending challenge");

        MockMobileClient.Response stale = mockMobileClient.approveLogin(firstChallenge.confirmToken());
        assertTrue(
                stale.responseStatus() >= 400 || stale.httpStatus() >= 400,
                () -> "Stale challenge should fail but got " + describe(stale));

        MockMobileClient.Response refreshed = mockMobileClient.approveLogin(refreshedChallenge.confirmToken());
        assertEquals(200, refreshed.httpStatus(), () -> describe(refreshed));
        assertEquals(200, refreshed.responseStatus(), () -> describe(refreshed));

        pushSession.completePushChallenge(refreshedChallenge.formAction());
    }

    @Test
    void mockApprovesLoginWithNumberMatch() throws Exception {
        adminClient.resetUserState(TEST_USERNAME);
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_NUMBER_MATCH);
        enrollWithMockDevice();

        BrowserSession pushSession = new BrowserSession(baseUri);
        HtmlPage loginPage = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(loginPage, TEST_USERNAME, TEST_USERNAME);
        BrowserSession.DeviceChallenge challenge = pushSession.extractDeviceChallenge(waitingPage);
        String displayed = pushSession.extractUserVerification(waitingPage);
        assertTrue(
                displayed != null && displayed.matches("^(0|[1-9][0-9]?)$"),
                "Expected number-match value 0-99 but got: " + displayed);

        MockMobileClient.Response approval = mockMobileClient.approveLogin(challenge.confirmToken(), displayed);
        assertEquals(200, approval.httpStatus(), () -> describe(approval));
        assertEquals(200, approval.responseStatus(), () -> describe(approval));

        pushSession.completePushChallenge(challenge.formAction());
    }

    @Test
    void mockRejectsWrongNumberMatchSelection() throws Exception {
        adminClient.resetUserState(TEST_USERNAME);
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_NUMBER_MATCH);
        enrollWithMockDevice();

        BrowserSession pushSession = new BrowserSession(baseUri);
        HtmlPage loginPage = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(loginPage, TEST_USERNAME, TEST_USERNAME);
        BrowserSession.DeviceChallenge challenge = pushSession.extractDeviceChallenge(waitingPage);
        String displayed = pushSession.extractUserVerification(waitingPage);
        assertTrue(
                displayed != null && displayed.matches("^(0|[1-9][0-9]?)$"),
                "Expected number-match value 0-99 but got: " + displayed);

        String wrong = "0".equals(displayed) ? "1" : "0";
        MockMobileClient.Response rejected = mockMobileClient.approveLogin(challenge.confirmToken(), wrong);
        assertEquals(403, rejected.httpStatus(), () -> "Expected 403 but got: " + describe(rejected));
        assertTrue(
                (rejected.error() != null && rejected.error().contains("User verification mismatch")),
                () -> "Expected mismatch error but got: " + describe(rejected));

        MockMobileClient.Response approval = mockMobileClient.approveLogin(challenge.confirmToken(), displayed);
        assertEquals(200, approval.httpStatus(), () -> describe(approval));
        assertEquals(200, approval.responseStatus(), () -> describe(approval));
        pushSession.completePushChallenge(challenge.formAction());
    }

    @Test
    void mockApprovesLoginWithPin() throws Exception {
        adminClient.resetUserState(TEST_USERNAME);
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_PIN);
        enrollWithMockDevice();

        BrowserSession pushSession = new BrowserSession(baseUri);
        HtmlPage loginPage = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(loginPage, TEST_USERNAME, TEST_USERNAME);
        BrowserSession.DeviceChallenge challenge = pushSession.extractDeviceChallenge(waitingPage);
        String pin = pushSession.extractUserVerification(waitingPage);
        assertTrue(pin != null && pin.matches("\\d{4}"), "Expected 4-digit pin but got: " + pin);

        MockMobileClient.Response approval = mockMobileClient.approveLogin(challenge.confirmToken(), pin);
        assertEquals(200, approval.httpStatus(), () -> describe(approval));
        assertEquals(200, approval.responseStatus(), () -> describe(approval));

        pushSession.completePushChallenge(challenge.formAction());
    }

    @Test
    void mockRejectsWrongPin() throws Exception {
        adminClient.resetUserState(TEST_USERNAME);
        adminClient.configurePushMfaUserVerification(PushMfaConstants.USER_VERIFICATION_PIN);
        enrollWithMockDevice();

        BrowserSession pushSession = new BrowserSession(baseUri);
        HtmlPage loginPage = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(loginPage, TEST_USERNAME, TEST_USERNAME);
        BrowserSession.DeviceChallenge challenge = pushSession.extractDeviceChallenge(waitingPage);
        String pin = pushSession.extractUserVerification(waitingPage);
        assertTrue(pin != null && pin.matches("\\d{4}"), "Expected 4-digit pin but got: " + pin);

        String wrong = "0000".equals(pin) ? "0001" : "0000";
        MockMobileClient.Response rejected = mockMobileClient.approveLogin(challenge.confirmToken(), wrong);
        assertEquals(403, rejected.httpStatus(), () -> "Expected 403 but got: " + describe(rejected));
        assertTrue(
                (rejected.error() != null && rejected.error().contains("User verification mismatch")),
                () -> "Expected mismatch error but got: " + describe(rejected));

        MockMobileClient.Response approval = mockMobileClient.approveLogin(challenge.confirmToken(), pin);
        assertEquals(200, approval.httpStatus(), () -> describe(approval));
        assertEquals(200, approval.responseStatus(), () -> describe(approval));
        pushSession.completePushChallenge(challenge.formAction());
    }

    private void enrollWithMockDevice() throws Exception {
        EnrollmentFlow enrollment = startEnrollmentFlow();
        MockMobileClient.Response response = mockMobileClient.enroll(enrollment.enrollmentToken());
        assertEquals(200, response.httpStatus(), () -> describe(response));
        assertEquals(200, response.responseStatus(), () -> describe(response));
        enrollment.session().submitEnrollmentCheck(enrollment.enrollmentPage());
    }

    private EnrollmentFlow startEnrollmentFlow() throws Exception {
        BrowserSession enrollmentSession = new BrowserSession(baseUri);
        HtmlPage loginPage = enrollmentSession.startAuthorization("test-app");
        HtmlPage enrollmentPage = enrollmentSession.submitLogin(loginPage, TEST_USERNAME, TEST_USERNAME);
        String enrollmentToken = enrollmentSession.extractEnrollmentToken(enrollmentPage);
        return new EnrollmentFlow(enrollmentSession, enrollmentPage, enrollmentToken);
    }

    private String describe(MockMobileClient.Response response) {
        return "HTTP " + response.httpStatus() + " body=" + response.payload();
    }

    private String subjectFromToken(String token) throws Exception {
        return SignedJWT.parse(token).getJWTClaimsSet().getSubject();
    }

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

    private record EnrollmentFlow(BrowserSession session, HtmlPage enrollmentPage, String enrollmentToken) {}
}
