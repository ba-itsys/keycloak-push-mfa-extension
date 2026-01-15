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

package de.arbeitsagentur.keycloak.push;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
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
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

/**
 * Security-focused integration tests covering OWASP Top 10:2025 and other vulnerabilities.
 */
@Testcontainers
@ExtendWith(ContainerLogWatcher.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PushMfaSecurityIT {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path EXTENSION_JAR = locateProviderJar();
    private static final Path REALM_FILE =
            Paths.get("config", "demo-realm.json").toAbsolutePath();
    private static final String TEST_USERNAME = "sectest";
    private static final String TEST_PASSWORD = "sectest";
    private static final String ATTACKER_USERNAME = "attacker";
    private static final String ATTACKER_PASSWORD = "attacker";
    private static final int MAX_RETRIES = 3;

    @Container
    private static final GenericContainer<?> KEYCLOAK = new GenericContainer<>("quay.io/keycloak/keycloak:26.4.5")
            .withExposedPorts(8080)
            .withCopyFileToContainer(MountableFile.forHostPath(EXTENSION_JAR), "/opt/keycloak/providers/extension.jar")
            .withCopyFileToContainer(MountableFile.forHostPath(REALM_FILE), "/opt/keycloak/data/import/demo-realm.json")
            .withEnv("KEYCLOAK_ADMIN", "admin")
            .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
            .withCommand(
                    "start-dev --hostname=localhost --hostname-strict=false --http-enabled=true --import-realm --features=dpop")
            .waitingFor(Wait.forHttp("/realms/master").forStatusCode(200))
            .withStartupTimeout(Duration.ofMinutes(3));

    private final HttpClient http =
            HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    private URI baseUri;
    private AdminClient adminClient;

    @BeforeAll
    void setup() throws Exception {
        baseUri = URI.create(String.format("http://%s:%d/", KEYCLOAK.getHost(), KEYCLOAK.getMappedPort(8080)));
        adminClient = new AdminClient(baseUri);
        adminClient.ensureUser(TEST_USERNAME, TEST_PASSWORD);
        adminClient.ensureUser(ATTACKER_USERNAME, ATTACKER_PASSWORD);
    }

    @BeforeEach
    void resetConfig() throws Exception {
        adminClient.resetAccessToken();
        adminClient.configurePushMfaUserVerification(
                PushMfaConstants.USER_VERIFICATION_NONE, PushMfaConstants.DEFAULT_USER_VERIFICATION_PIN_LENGTH);
        try {
            adminClient.logoutAllSessions(TEST_USERNAME);
        } catch (Exception e) {
            // User might not have sessions
        }
        try {
            adminClient.logoutAllSessions(ATTACKER_USERNAME);
        } catch (Exception e) {
            // User might not have sessions
        }
    }

    private static Path locateProviderJar() {
        Path target = Paths.get("target");
        try (var files = Files.list(target)) {
            return files.filter(p -> p.getFileName().toString().matches("keycloak-push-mfa-extension-.*\\.jar"))
                    .filter(p -> !p.getFileName().toString().contains("-sources"))
                    .filter(p -> !p.getFileName().toString().contains("-javadoc"))
                    .findFirst()
                    .orElse(target.resolve("keycloak-push-mfa-extension.jar"));
        } catch (Exception e) {
            return target.resolve("keycloak-push-mfa-extension.jar");
        }
    }

    private DeviceClient enrollDeviceWithRetry(String username, String password) throws Exception {
        for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            try {
                adminClient.resetAccessToken();
                adminClient.resetUserState(username);
                DeviceState state = DeviceState.create(DeviceKeyType.RSA);
                DeviceClient device = new DeviceClient(baseUri, state);
                BrowserSession session = new BrowserSession(baseUri);
                HtmlPage login = session.startAuthorization("test-app");
                HtmlPage enrollPage = session.submitLogin(login, username, password);
                String token = session.extractEnrollmentToken(enrollPage);
                device.completeEnrollment(token);
                session.submitEnrollmentCheck(enrollPage);
                return device;
            } catch (Exception e) {
                if (attempt == MAX_RETRIES - 1) throw e;
                Thread.sleep(2000);
            }
        }
        throw new IllegalStateException("Failed to enroll device after retries");
    }

    private URI realmUri() {
        return baseUri.resolve("/realms/demo/");
    }

    // ==================== A01:2025 – Broken Access Control ====================

    @Nested
    @DisplayName("A01:2025 – Broken Access Control")
    class BrokenAccessControl {

        @Test
        @DisplayName("Random challenge ID returns 404")
        void randomChallengeIdReturns404() throws Exception {
            DeviceClient device = enrollDeviceWithRetry(TEST_USERNAME, TEST_PASSWORD);
            String fakeConfirmToken = createFakeConfirmToken(device.state().credentialId());

            HttpResponse<String> response = device.respondToChallengeRaw(
                    fakeConfirmToken, UUID.randomUUID().toString(), "approve");

            assertEquals(404, response.statusCode());
        }
    }

    // ==================== A04:2025 – Cryptographic Failures ====================

    @Nested
    @DisplayName("A04:2025 – Cryptographic Failures")
    class CryptographicFailures {

        @Test
        @DisplayName("Expired enrollment token rejected")
        void expiredEnrollmentTokenRejected() throws Exception {
            adminClient.resetUserState(TEST_USERNAME);
            DeviceState state = DeviceState.create(DeviceKeyType.RSA);

            JWTClaimsSet expiredClaims = new JWTClaimsSet.Builder()
                    .claim("enrollmentId", UUID.randomUUID().toString())
                    .claim("nonce", "test-nonce")
                    .subject("fake-user-id")
                    .claim("deviceType", "ios")
                    .claim("pushProviderId", "test")
                    .claim("pushProviderType", "log")
                    .claim("credentialId", state.credentialId())
                    .claim("deviceId", state.deviceId())
                    .expirationTime(Date.from(Instant.now().minusSeconds(3600)))
                    .claim("cnf", Map.of("jwk", state.signingKey().publicJwk().toJSONObject()))
                    .build();

            SignedJWT token = signWithDeviceKey(state.signingKey(), expiredClaims);

            HttpRequest request = HttpRequest.newBuilder(realmUri().resolve("push-mfa/enroll/complete"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"" + token.serialize() + "\"}"))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

            assertNotEquals(200, response.statusCode(), "Expired token should be rejected");
        }
    }

    // ==================== A05:2025 – Injection ====================

    @Nested
    @DisplayName("A05:2025 – Injection")
    class Injection {

        @Test
        @DisplayName("Oversized JWT rejected")
        void oversizedJwtRejected() throws Exception {
            String hugePayload = "A".repeat(100000);
            String fakeJwt = "eyJhbGciOiJSUzI1NiJ9." + Base64.getUrlEncoder().encodeToString(hugePayload.getBytes())
                    + ".fakesig";

            HttpRequest request = HttpRequest.newBuilder(realmUri().resolve("push-mfa/enroll/complete"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"" + fakeJwt + "\"}"))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

            assertTrue(response.statusCode() >= 400, "Oversized JWT should be rejected");
        }
    }

    // ==================== A07:2025 – Authentication Failures ====================

    @Nested
    @DisplayName("A07:2025 – Authentication Failures")
    class AuthenticationFailures {

        @Test
        @DisplayName("Missing Authorization header rejected")
        void missingAuthorizationHeaderRejected() throws Exception {
            DeviceClient device = enrollDeviceWithRetry(TEST_USERNAME, TEST_PASSWORD);

            URI pendingUri = realmUri()
                    .resolve("push-mfa/login/pending?userId=" + device.state().userId());
            HttpRequest request = HttpRequest.newBuilder(pendingUri)
                    .header(
                            "DPoP",
                            device.createDpopProof(
                                    "GET", pendingUri, UUID.randomUUID().toString()))
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

            assertEquals(401, response.statusCode());
        }

        @Test
        @DisplayName("Missing DPoP header rejected")
        void missingDpopHeaderRejected() throws Exception {
            DeviceClient device = enrollDeviceWithRetry(TEST_USERNAME, TEST_PASSWORD);

            URI pendingUri = realmUri()
                    .resolve("push-mfa/login/pending?userId=" + device.state().userId());
            HttpRequest request = HttpRequest.newBuilder(pendingUri)
                    .header("Authorization", "DPoP " + device.accessToken())
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

            assertEquals(401, response.statusCode());
        }

        @Test
        @DisplayName("Bearer token rejected for DPoP endpoints")
        void bearerTokenRejectedForDpopEndpoints() throws Exception {
            DeviceClient device = enrollDeviceWithRetry(TEST_USERNAME, TEST_PASSWORD);

            URI pendingUri = realmUri()
                    .resolve("push-mfa/login/pending?userId=" + device.state().userId());
            HttpRequest request = HttpRequest.newBuilder(pendingUri)
                    .header("Authorization", "Bearer " + device.accessToken())
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

            assertEquals(401, response.statusCode(), "Bearer token should be rejected for DPoP-protected endpoints");
        }

        @Test
        @DisplayName("DPoP with wrong HTTP method rejected")
        void dpopWithWrongMethodRejected() throws Exception {
            DeviceClient device = enrollDeviceWithRetry(TEST_USERNAME, TEST_PASSWORD);

            URI pendingUri = realmUri()
                    .resolve("push-mfa/login/pending?userId=" + device.state().userId());
            String wrongMethodProof =
                    device.createDpopProof("POST", pendingUri, UUID.randomUUID().toString());

            HttpRequest request = HttpRequest.newBuilder(pendingUri)
                    .header("Authorization", "DPoP " + device.accessToken())
                    .header("DPoP", wrongMethodProof)
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

            assertTrue(
                    response.statusCode() == 401 || response.statusCode() == 403,
                    "DPoP with wrong method should be rejected with 401 or 403, got: " + response.statusCode());
        }

        @Test
        @DisplayName("DPoP with wrong URL rejected")
        void dpopWithWrongUrlRejected() throws Exception {
            DeviceClient device = enrollDeviceWithRetry(TEST_USERNAME, TEST_PASSWORD);

            URI pendingUri = realmUri()
                    .resolve("push-mfa/login/pending?userId=" + device.state().userId());
            URI wrongUri = realmUri().resolve("push-mfa/device/push-provider");
            String wrongUrlProof =
                    device.createDpopProof("GET", wrongUri, UUID.randomUUID().toString());

            HttpRequest request = HttpRequest.newBuilder(pendingUri)
                    .header("Authorization", "DPoP " + device.accessToken())
                    .header("DPoP", wrongUrlProof)
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

            assertTrue(
                    response.statusCode() == 401 || response.statusCode() == 403,
                    "DPoP with wrong URL should be rejected with 401 or 403, got: " + response.statusCode());
        }
    }

    // ==================== Denial of Service ====================

    @Nested
    @DisplayName("Denial of Service")
    class DenialOfService {

        @Test
        @DisplayName("Malformed JSON rejected quickly")
        void malformedJsonRejectedQuickly() throws Exception {
            String malformedJson = "{\"token\": \"test\", invalid}";

            long start = System.currentTimeMillis();
            HttpRequest request = HttpRequest.newBuilder(realmUri().resolve("push-mfa/enroll/complete"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(malformedJson))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            long duration = System.currentTimeMillis() - start;

            assertTrue(response.statusCode() >= 400, "Malformed JSON should be rejected");
            assertTrue(duration < 5000, "Malformed JSON should be rejected quickly");
        }
    }

    // ==================== SSE Security ====================

    @Nested
    @DisplayName("SSE Security")
    class SseSecurity {

        @Test
        @DisplayName("SSE endpoint for non-existent challenge returns error")
        void sseForNonExistentChallengeReturnsError() throws Exception {
            String fakeId = UUID.randomUUID().toString();
            URI sseUri = realmUri().resolve("push-mfa/login/challenges/" + fakeId + "/events?secret=test");
            HttpRequest request = HttpRequest.newBuilder(sseUri)
                    .header("Accept", "text/event-stream")
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

            assertTrue(
                    response.statusCode() == 404 || response.body().contains("NOT_FOUND"),
                    "Non-existent challenge should return 404 or NOT_FOUND status");
        }
    }

    // ==================== Credential Lifecycle Attacks ====================

    @Nested
    @DisplayName("Credential Lifecycle Attacks")
    class CredentialLifecycle {

        @Test
        @DisplayName("Re-enrollment creates new credential")
        void reEnrollmentCreatesNewCredential() throws Exception {
            DeviceClient device1 = enrollDeviceWithRetry(TEST_USERNAME, TEST_PASSWORD);
            String credId1 = device1.state().credentialId();

            adminClient.deleteUserCredentials(TEST_USERNAME);

            DeviceClient device2 = enrollDeviceWithRetry(TEST_USERNAME, TEST_PASSWORD);
            String credId2 = device2.state().credentialId();

            assertNotEquals(credId1, credId2, "Re-enrollment should create new credential");
        }
    }

    // ==================== Timing Attacks ====================

    @Nested
    @DisplayName("Timing Attacks")
    class TimingAttacks {

        private static final int WARMUP_ITERATIONS = 3;
        private static final int TIMING_SAMPLES = 20;
        // For valid auth where we do DB lookup, allow some variance
        private static final double MAX_TIMING_VARIANCE_RATIO_AUTHENTICATED = 2.0;
        // For invalid/missing auth, check fails before any user lookup - should be nearly identical
        private static final double MAX_TIMING_VARIANCE_RATIO_AUTH_FAIL = 1.3;

        @Test
        @DisplayName("Valid user with no challenges returns empty list")
        void validUserNoChallengesReturnsEmptyList() throws Exception {
            DeviceClient device = enrollDeviceWithRetry(TEST_USERNAME, TEST_PASSWORD);

            URI validUri = realmUri()
                    .resolve("push-mfa/login/pending?userId=" + device.state().userId());
            HttpRequest validRequest = HttpRequest.newBuilder(validUri)
                    .header("Authorization", "DPoP " + device.accessToken())
                    .header(
                            "DPoP",
                            device.createDpopProof(
                                    "GET", validUri, UUID.randomUUID().toString()))
                    .GET()
                    .build();
            HttpResponse<String> validResponse = http.send(validRequest, HttpResponse.BodyHandlers.ofString());

            assertEquals(200, validResponse.statusCode());
            JsonNode validBody = MAPPER.readTree(validResponse.body());
            assertEquals(0, validBody.path("challenges").size());
        }

        @Test
        @DisplayName("Unauthorized userId request has similar timing regardless of user existence")
        void unauthorizedUserIdRequestHasSimilarTiming() throws Exception {
            DeviceClient device = enrollDeviceWithRetry(TEST_USERNAME, TEST_PASSWORD);
            String nonExistentUserId = UUID.randomUUID().toString();

            // Warmup phase to avoid cold-start effects
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                URI warmupUri = realmUri()
                        .resolve("push-mfa/login/pending?userId="
                                + device.state().userId());
                HttpRequest warmupRequest = HttpRequest.newBuilder(warmupUri)
                        .header("Authorization", "DPoP " + device.accessToken())
                        .header(
                                "DPoP",
                                device.createDpopProof(
                                        "GET", warmupUri, UUID.randomUUID().toString()))
                        .GET()
                        .build();
                http.send(warmupRequest, HttpResponse.BodyHandlers.ofString());
            }

            long[] validUserTimes = new long[TIMING_SAMPLES];
            long[] invalidUserTimes = new long[TIMING_SAMPLES];

            for (int i = 0; i < TIMING_SAMPLES; i++) {
                URI validUri = realmUri()
                        .resolve("push-mfa/login/pending?userId="
                                + device.state().userId());
                HttpRequest validRequest = HttpRequest.newBuilder(validUri)
                        .header("Authorization", "DPoP " + device.accessToken())
                        .header(
                                "DPoP",
                                device.createDpopProof(
                                        "GET", validUri, UUID.randomUUID().toString()))
                        .GET()
                        .build();

                long startValid = System.nanoTime();
                HttpResponse<String> validResponse = http.send(validRequest, HttpResponse.BodyHandlers.ofString());
                validUserTimes[i] = System.nanoTime() - startValid;

                assertEquals(200, validResponse.statusCode());
                JsonNode validBody = MAPPER.readTree(validResponse.body());
                assertEquals(0, validBody.path("challenges").size(), "Valid user should return empty list");

                URI invalidUri = realmUri().resolve("push-mfa/login/pending?userId=" + nonExistentUserId);
                HttpRequest invalidRequest = HttpRequest.newBuilder(invalidUri)
                        .header("Authorization", "DPoP " + device.accessToken())
                        .header(
                                "DPoP",
                                device.createDpopProof(
                                        "GET", invalidUri, UUID.randomUUID().toString()))
                        .GET()
                        .build();

                long startInvalid = System.nanoTime();
                HttpResponse<String> invalidResponse = http.send(invalidRequest, HttpResponse.BodyHandlers.ofString());
                invalidUserTimes[i] = System.nanoTime() - startInvalid;

                assertEquals(
                        200, invalidResponse.statusCode(), "Non-matching userId should return 200 with empty list");
                JsonNode invalidBody = MAPPER.readTree(invalidResponse.body());
                assertEquals(0, invalidBody.path("challenges").size(), "Non-matching userId should return empty list");
            }

            double validMedian = calculateMedian(validUserTimes);
            double invalidMedian = calculateMedian(invalidUserTimes);
            double ratio = Math.max(validMedian, invalidMedian) / Math.min(validMedian, invalidMedian);

            assertTrue(
                    ratio < MAX_TIMING_VARIANCE_RATIO_AUTHENTICATED,
                    String.format(
                            "Timing difference too large (ratio: %.2f). "
                                    + "Valid user median: %.2fms, Invalid user median: %.2fms. "
                                    + "This could allow user enumeration attacks via timing.",
                            ratio, validMedian / 1_000_000.0, invalidMedian / 1_000_000.0));
        }

        @Test
        @DisplayName("Without valid DPoP, no timing difference between existing and non-existing users")
        void noDpopNoTimingDifferenceForUserEnumeration() throws Exception {
            DeviceClient device = enrollDeviceWithRetry(TEST_USERNAME, TEST_PASSWORD);
            String existingUserId = device.state().userId();
            String nonExistentUserId = UUID.randomUUID().toString();

            // Warmup
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                URI warmupUri = realmUri().resolve("push-mfa/login/pending?userId=" + existingUserId);
                HttpRequest warmupRequest = HttpRequest.newBuilder(warmupUri)
                        .header("Authorization", "DPoP invalid-token")
                        .header("DPoP", "invalid-dpop-proof")
                        .GET()
                        .build();
                http.send(warmupRequest, HttpResponse.BodyHandlers.ofString());
            }

            long[] existingUserTimes = new long[TIMING_SAMPLES];
            long[] nonExistingUserTimes = new long[TIMING_SAMPLES];

            for (int i = 0; i < TIMING_SAMPLES; i++) {
                URI existingUri = realmUri().resolve("push-mfa/login/pending?userId=" + existingUserId);
                HttpRequest existingRequest = HttpRequest.newBuilder(existingUri)
                        .header("Authorization", "DPoP invalid-token")
                        .header("DPoP", "invalid-dpop-proof")
                        .GET()
                        .build();

                long startExisting = System.nanoTime();
                HttpResponse<String> existingResponse =
                        http.send(existingRequest, HttpResponse.BodyHandlers.ofString());
                existingUserTimes[i] = System.nanoTime() - startExisting;

                assertTrue(
                        existingResponse.statusCode() == 401 || existingResponse.statusCode() == 403,
                        "Invalid DPoP should be rejected");

                URI nonExistingUri = realmUri().resolve("push-mfa/login/pending?userId=" + nonExistentUserId);
                HttpRequest nonExistingRequest = HttpRequest.newBuilder(nonExistingUri)
                        .header("Authorization", "DPoP invalid-token")
                        .header("DPoP", "invalid-dpop-proof")
                        .GET()
                        .build();

                long startNonExisting = System.nanoTime();
                HttpResponse<String> nonExistingResponse =
                        http.send(nonExistingRequest, HttpResponse.BodyHandlers.ofString());
                nonExistingUserTimes[i] = System.nanoTime() - startNonExisting;

                assertTrue(
                        nonExistingResponse.statusCode() == 401 || nonExistingResponse.statusCode() == 403,
                        "Invalid DPoP should be rejected");
            }

            double existingMedian = calculateMedian(existingUserTimes);
            double nonExistingMedian = calculateMedian(nonExistingUserTimes);
            double ratio = Math.max(existingMedian, nonExistingMedian) / Math.min(existingMedian, nonExistingMedian);

            assertTrue(
                    ratio < MAX_TIMING_VARIANCE_RATIO_AUTH_FAIL,
                    String.format(
                            "Timing difference with invalid DPoP too large (ratio: %.2f). "
                                    + "Auth check should fail before any user-specific logic. "
                                    + "Existing user median: %.2fms, Non-existing user median: %.2fms.",
                            ratio, existingMedian / 1_000_000.0, nonExistingMedian / 1_000_000.0));
        }

        @Test
        @DisplayName("Without Authorization header, no timing difference between existing and non-existing users")
        void noAuthorizationNoTimingDifferenceForUserEnumeration() throws Exception {
            DeviceClient device = enrollDeviceWithRetry(TEST_USERNAME, TEST_PASSWORD);
            String existingUserId = device.state().userId();
            String nonExistentUserId = UUID.randomUUID().toString();

            // Warmup
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                URI warmupUri = realmUri().resolve("push-mfa/login/pending?userId=" + existingUserId);
                HttpRequest warmupRequest =
                        HttpRequest.newBuilder(warmupUri).GET().build();
                http.send(warmupRequest, HttpResponse.BodyHandlers.ofString());
            }

            long[] existingUserTimes = new long[TIMING_SAMPLES];
            long[] nonExistingUserTimes = new long[TIMING_SAMPLES];

            for (int i = 0; i < TIMING_SAMPLES; i++) {
                URI existingUri = realmUri().resolve("push-mfa/login/pending?userId=" + existingUserId);
                HttpRequest existingRequest =
                        HttpRequest.newBuilder(existingUri).GET().build();

                long startExisting = System.nanoTime();
                HttpResponse<String> existingResponse =
                        http.send(existingRequest, HttpResponse.BodyHandlers.ofString());
                existingUserTimes[i] = System.nanoTime() - startExisting;

                assertEquals(401, existingResponse.statusCode(), "Missing auth should return 401");

                URI nonExistingUri = realmUri().resolve("push-mfa/login/pending?userId=" + nonExistentUserId);
                HttpRequest nonExistingRequest =
                        HttpRequest.newBuilder(nonExistingUri).GET().build();

                long startNonExisting = System.nanoTime();
                HttpResponse<String> nonExistingResponse =
                        http.send(nonExistingRequest, HttpResponse.BodyHandlers.ofString());
                nonExistingUserTimes[i] = System.nanoTime() - startNonExisting;

                assertEquals(401, nonExistingResponse.statusCode(), "Missing auth should return 401");
            }

            double existingMedian = calculateMedian(existingUserTimes);
            double nonExistingMedian = calculateMedian(nonExistingUserTimes);
            double ratio = Math.max(existingMedian, nonExistingMedian) / Math.min(existingMedian, nonExistingMedian);

            assertTrue(
                    ratio < MAX_TIMING_VARIANCE_RATIO_AUTH_FAIL,
                    String.format(
                            "Timing difference without auth too large (ratio: %.2f). "
                                    + "Auth check should fail before any user-specific logic. "
                                    + "Existing user median: %.2fms, Non-existing user median: %.2fms.",
                            ratio, existingMedian / 1_000_000.0, nonExistingMedian / 1_000_000.0));
        }

        private double calculateMedian(long[] values) {
            long[] sorted = values.clone();
            java.util.Arrays.sort(sorted);
            int mid = sorted.length / 2;
            if (sorted.length % 2 == 0) {
                return (sorted[mid - 1] + sorted[mid]) / 2.0;
            } else {
                return sorted[mid];
            }
        }
    }

    // ==================== Helper Methods ====================

    private String createFakeConfirmToken(String credentialId) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("credId", credentialId)
                .claim("cid", UUID.randomUUID().toString())
                .claim("typ", 1)
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .build();

        DeviceState fakeDevice = DeviceState.create(DeviceKeyType.RSA);
        return signWithDeviceKey(fakeDevice.signingKey(), claims).serialize();
    }

    private SignedJWT signWithDeviceKey(DeviceSigningKey key, JWTClaimsSet claims) throws Exception {
        JWSHeader header = new JWSHeader.Builder(key.algorithm())
                .type(JOSEObjectType.JWT)
                .keyID(key.keyId())
                .build();
        SignedJWT token = new SignedJWT(header, claims);
        token.sign(key.signer());
        return token;
    }
}
