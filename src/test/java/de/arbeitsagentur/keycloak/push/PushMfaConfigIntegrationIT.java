package de.arbeitsagentur.keycloak.push;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.arbeitsagentur.keycloak.push.support.AdminClient;
import de.arbeitsagentur.keycloak.push.support.BrowserSession;
import de.arbeitsagentur.keycloak.push.support.DeviceClient;
import de.arbeitsagentur.keycloak.push.support.DeviceKeyType;
import de.arbeitsagentur.keycloak.push.support.DeviceState;
import de.arbeitsagentur.keycloak.push.support.HtmlPage;
import java.io.InputStream;
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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

@Testcontainers
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PushMfaConfigIntegrationIT {

    private static final Path EXTENSION_JAR = locateProviderJar();
    private static final Path REALM_FILE =
            Paths.get("config", "demo-realm.json").toAbsolutePath();
    private static final String TEST_USERNAME = "test";
    private static final String TEST_PASSWORD = "test";

    @Container
    private static final GenericContainer<?> KEYCLOAK = new GenericContainer<>("quay.io/keycloak/keycloak:26.4.5")
            .withExposedPorts(8080)
            .withCopyFileToContainer(
                    MountableFile.forHostPath(EXTENSION_JAR), "/opt/keycloak/providers/keycloak-push-mfa.jar")
            .withCopyFileToContainer(MountableFile.forHostPath(REALM_FILE), "/opt/keycloak/data/import/demo-realm.json")
            .withEnv("KEYCLOAK_ADMIN", "admin")
            .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
            .withEnv(
                    "JAVA_OPTS_APPEND",
                    String.join(
                            " ",
                            "-Dkeycloak.push-mfa.input.maxJwtLength=2048",
                            "-Dkeycloak.push-mfa.dpop.jtiMaxLength=40",
                            "-Dkeycloak.push-mfa.sse.maxConnections=1"))
            .withCommand(
                    "start-dev",
                    "--hostname=localhost",
                    "--hostname-strict=false",
                    "--http-enabled=true",
                    "--import-realm",
                    "--features=dpop")
            .waitingFor(Wait.forHttp("/realms/master").forStatusCode(200))
            .withStartupTimeout(Duration.ofMinutes(3));

    private URI baseUri;
    private AdminClient adminClient;

    @BeforeAll
    void setup() {
        baseUri = URI.create(String.format("http://%s:%d/", KEYCLOAK.getHost(), KEYCLOAK.getMappedPort(8080)));
        adminClient = new AdminClient(baseUri);
    }

    @Test
    void configuredJwtLimitIsEnforced() throws Exception {
        HttpClient httpClient =
                HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
        URI pendingUri = baseUri.resolve("/realms/demo/push-mfa/login/pending?userId=test");
        String oversizedToken = "a".repeat(2049);

        HttpRequest request = HttpRequest.newBuilder(pendingUri)
                .header("Authorization", "DPoP " + oversizedToken)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(400, response.statusCode(), () -> "Expected maxJwtLength=2048 rejection: " + response.body());
    }

    @Test
    void configuredDpopJtiMaxLengthIsEnforced() throws Exception {
        try {
            DeviceClient deviceClient = enrollDevice(DeviceKeyType.RSA);
            HttpClient httpClient =
                    HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();

            String encodedUserId = URLEncoder.encode(deviceClient.state().userId(), StandardCharsets.UTF_8);
            URI pendingUri = baseUri.resolve("/realms/demo/push-mfa/login/pending?userId=" + encodedUserId);
            String oversizedJti = "a".repeat(41);
            String proof = deviceClient.createDpopProof("GET", pendingUri, oversizedJti);

            HttpRequest request = HttpRequest.newBuilder(pendingUri)
                    .header("Authorization", "DPoP " + deviceClient.accessToken())
                    .header("DPoP", proof)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(400, response.statusCode(), () -> "Expected jtiMaxLength=40 rejection: " + response.body());
        } catch (Exception ex) {
            System.err.println("Keycloak container logs:\n" + KEYCLOAK.getLogs());
            throw ex;
        }
    }

    @Test
    void configuredSseMaxConnectionsIsEnforced() throws Exception {
        try {
            adminClient.resetUserState(TEST_USERNAME);
            BrowserSession browser = new BrowserSession(baseUri);
            HtmlPage loginPage = browser.startAuthorization("test-app");
            HtmlPage enrollmentPage = browser.submitLogin(loginPage, TEST_USERNAME, TEST_PASSWORD);

            URI eventsUri = browser.extractEnrollmentEventsUri(enrollmentPage);
            HttpClient httpClient =
                    HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();

            InputStream firstBody = null;
            try {
                HttpResponse<InputStream> first = httpClient.send(
                        HttpRequest.newBuilder(eventsUri)
                                .header("Accept", "text/event-stream")
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofInputStream());
                assertEquals(200, first.statusCode(), () -> "SSE connection failed: " + first.body());
                firstBody = first.body();

                HttpResponse<String> second = httpClient.send(
                        HttpRequest.newBuilder(eventsUri)
                                .timeout(Duration.ofSeconds(5))
                                .header("Accept", "text/event-stream")
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
                assertEquals(200, second.statusCode(), () -> "Second SSE request failed: " + second.body());
                assertTrue(
                        second.body().contains("TOO_MANY_CONNECTIONS"),
                        () -> "Second SSE response should be rejected: " + second.body());
            } finally {
                if (firstBody != null) {
                    firstBody.close();
                }
            }
        } catch (Exception ex) {
            System.err.println("Keycloak container logs:\n" + KEYCLOAK.getLogs());
            throw ex;
        }
    }

    private DeviceClient enrollDevice(DeviceKeyType keyType) throws Exception {
        adminClient.resetUserState(TEST_USERNAME);
        DeviceState deviceState = DeviceState.create(keyType);
        DeviceClient deviceClient = new DeviceClient(baseUri, deviceState);

        BrowserSession enrollmentSession = new BrowserSession(baseUri);
        HtmlPage loginPage = enrollmentSession.startAuthorization("test-app");
        HtmlPage enrollmentPage = enrollmentSession.submitLogin(loginPage, TEST_USERNAME, TEST_PASSWORD);
        String enrollmentToken = enrollmentSession.extractEnrollmentToken(enrollmentPage);
        deviceClient.completeEnrollment(enrollmentToken);
        enrollmentSession.submitEnrollmentCheck(enrollmentPage);
        return deviceClient;
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
}
