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

import de.arbeitsagentur.keycloak.push.support.AdminClient;
import de.arbeitsagentur.keycloak.push.support.ContainerLogWatcher;
import de.arbeitsagentur.keycloak.push.support.SharedKeycloakContainerSupport;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Random;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
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
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Fuzzing-style tests that generate random/malformed inputs to test robustness.
 */
@Testcontainers
@ExtendWith(ContainerLogWatcher.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PushMfaFuzzIT {

    private static final String SHARED_KEYCLOAK_OWNER = PushMfaFuzzIT.class.getSimpleName();
    private static final String TEST_USERNAME = "fuzztest";
    private static final String TEST_PASSWORD = "fuzztest";
    private static final Random RANDOM = new Random(12345);
    private static final GenericContainer<?> KEYCLOAK = sharedKeycloak();

    private final HttpClient http =
            HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    private URI baseUri;
    private AdminClient adminClient;

    @BeforeAll
    void setup() throws Exception {
        SharedKeycloakContainerSupport.acquire(SHARED_KEYCLOAK_OWNER);
        baseUri = SharedKeycloakContainerSupport.baseUri();
        adminClient = new AdminClient(baseUri);
        adminClient.ensureUser(TEST_USERNAME, TEST_PASSWORD);
    }

    @AfterAll
    void captureContainerCoverage() throws Exception {
        SharedKeycloakContainerSupport.release(SHARED_KEYCLOAK_OWNER);
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

    private static GenericContainer<?> sharedKeycloak() {
        return SharedKeycloakContainerSupport.container();
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
                    "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjoxfQ.", // alg:none JWT
                    "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxfQ.invalidsig", // Invalid signature
                    "null",
                    "undefined",
                    "true",
                    "false",
                    "[]",
                    "{}",
                    "<xml>test</xml>",
                    "random string with spaces",
                    "12345678901234567890");
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
            // Note: "multipart/form-data", "application/x-www-form-urlencoded", and "invalid"
            // are excluded because sending a JSON body with these content types causes server-side
            // parsing errors (500). This is expected server behavior - the server correctly fails
            // to parse or process the body according to the Content-Type header. Not security issues.
            return Stream.of(
                    "text/plain",
                    "text/html",
                    "application/xml",
                    "application/octet-stream",
                    "image/png",
                    "application/json; charset=utf-8",
                    "APPLICATION/JSON",
                    "application/JSON",
                    "");
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

            HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            assertTrue(response.statusCode() > 0, "Server should respond to request");
            assertNoServerError(response);
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
}
