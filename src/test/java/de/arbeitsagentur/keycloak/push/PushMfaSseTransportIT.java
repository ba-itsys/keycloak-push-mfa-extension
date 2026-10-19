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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.arbeitsagentur.keycloak.push.support.AdminClient;
import de.arbeitsagentur.keycloak.push.support.BrowserSession;
import de.arbeitsagentur.keycloak.push.support.ContainerLogWatcher;
import de.arbeitsagentur.keycloak.push.support.HtmlPage;
import de.arbeitsagentur.keycloak.push.support.KeycloakAdminBootstrap;
import de.arbeitsagentur.keycloak.push.support.KeycloakTestContainerSupport;
import de.arbeitsagentur.keycloak.push.support.SseClient;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Tests headers, heartbeats, connection rotation and the connection limit of the challenge SSE endpoints.
 *
 * <p>Keycloak runs with fewer worker threads than the tests keep streams open. If a stream held a worker thread,
 * later requests would time out.
 */
@Testcontainers
@ExtendWith(ContainerLogWatcher.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PushMfaSseTransportIT {

    private static final int WORKER_THREADS = 4;
    private static final int MAX_SSE_CONNECTIONS = 3 * WORKER_THREADS;
    private static final int HEARTBEAT_SECONDS = 5;
    private static final int MAX_CONNECTION_LIFETIME_SECONDS = 15;
    private static final long RECONNECT_DELAY_MILLIS = 1500L;
    private static final String PASSWORD = "sse-test";
    private static final Duration RESPONSE_TIMEOUT = Duration.ofSeconds(10);

    @Container
    private static final GenericContainer<?> KEYCLOAK = KeycloakTestContainerSupport.newKeycloakContainerWithOptions(
            "PushMfaSseTransportIT.exec",
            List.of(
                    "--http-pool-max-threads=" + WORKER_THREADS,
                    "--spi-push-mfa--default--sse-max-connections=" + MAX_SSE_CONNECTIONS,
                    "--spi-push-mfa--default--sse-heartbeat-interval-seconds=" + HEARTBEAT_SECONDS,
                    "--spi-push-mfa--default--sse-max-connection-lifetime-seconds=" + MAX_CONNECTION_LIFETIME_SECONDS,
                    "--spi-push-mfa--default--sse-reconnect-delay-millis=" + RECONNECT_DELAY_MILLIS));

    private URI baseUri;
    private AdminClient adminClient;

    @BeforeAll
    void setup() throws Exception {
        KeycloakAdminBootstrap.allowHttpAdminLogin(KEYCLOAK);
        baseUri = KeycloakTestContainerSupport.baseUri(KEYCLOAK);
        adminClient = new AdminClient(baseUri);
    }

    @Test
    @Order(1)
    void openStreamsDoNotHoldWorkerThreadsAndExcessStreamsAreRejected() throws Exception {
        List<URI> eventsUris = new ArrayList<>();
        for (int i = 0; i < MAX_SSE_CONNECTIONS; i++) {
            eventsUris.add(enrollmentEventsUri("sse-capacity-" + i));
        }

        List<SseClient> streams = new ArrayList<>();
        try {
            for (URI eventsUri : eventsUris) {
                SseClient stream = new SseClient(eventsUri);
                streams.add(stream);
                assertEquals(200, stream.awaitStatusCode(RESPONSE_TIMEOUT));
                assertEquals("PENDING", stream.awaitEvent(RESPONSE_TIMEOUT).status());
            }

            assertEquals(200, wellKnownStatus(), "Keycloak did not answer while streams were open");

            try (SseClient rejected = new SseClient(eventsUris.getFirst())) {
                assertEquals(200, rejected.awaitStatusCode(RESPONSE_TIMEOUT));
                SseClient.Event event = rejected.awaitEvent(RESPONSE_TIMEOUT);
                assertNotNull(event);
                assertEquals("TOO_MANY_CONNECTIONS", event.status());
                assertEquals(RECONNECT_DELAY_MILLIS, event.retry());
                assertEquals(
                        RECONNECT_DELAY_MILLIS,
                        event.json().path("retryAfterMillis").asLong());
                rejected.awaitEnd(RESPONSE_TIMEOUT);
            }
        } finally {
            streams.forEach(SseClient::close);
        }

        assertConnectionSlotIsReleased(eventsUris.getFirst());
    }

    @Test
    @Order(2)
    void pendingStreamSendsHeadersHeartbeatsAndRotatesConnection() throws Exception {
        URI eventsUri = enrollmentEventsUri("sse-lifecycle");

        try (SseClient stream = new SseClient(eventsUri)) {
            assertEquals(200, stream.awaitStatusCode(RESPONSE_TIMEOUT));
            assertSseHeaders(stream);

            SseClient.Event initial = stream.awaitEvent(RESPONSE_TIMEOUT);
            assertEquals("status", initial.name());
            assertEquals("PENDING", initial.status());
            assertNull(initial.retry(), "PENDING event has a retry field");

            SseClient.Event heartbeat = stream.awaitEvent(Duration.ofSeconds(HEARTBEAT_SECONDS + 5));
            assertNotNull(heartbeat, "No keepalive comment received");
            assertEquals("keepalive", heartbeat.comment());

            List<SseClient.Event> remaining = stream.awaitEnd(Duration.ofSeconds(MAX_CONNECTION_LIFETIME_SECONDS + 10));
            SseClient.Event rotation = remaining.getLast();
            assertEquals("PENDING", rotation.status());
            assertEquals(RECONNECT_DELAY_MILLIS, rotation.retry());
            assertEquals(
                    RECONNECT_DELAY_MILLIS,
                    rotation.json().path("retryAfterMillis").asLong());
            assertTrue(
                    remaining.subList(0, remaining.size() - 1).stream().allMatch(SseClient.Event::isComment),
                    "Unexpected events before rotation: " + remaining);
        }
    }

    @Test
    @Order(3)
    void rejectedStreamRequestsSendOneTerminalEventWithSseHeaders() throws Exception {
        URI eventsUri = enrollmentEventsUri("sse-rejections");
        URI withoutSecret = withQuery(eventsUri, null);
        URI unknownChallenge = URI.create(eventsUri
                .toString()
                .replaceFirst("/challenges/[^/]+/events", "/challenges/" + UUID.randomUUID() + "/events"));

        assertSingleTerminalEvent(withoutSecret, "INVALID");
        assertSingleTerminalEvent(unknownChallenge, "NOT_FOUND");
    }

    @Test
    @Order(4)
    void malformedChallengeIdIsRejectedBeforeStreaming() throws Exception {
        URI eventsUri = enrollmentEventsUri("sse-malformed");
        URI malformed = URI.create(
                eventsUri.toString().replaceFirst("/challenges/[^/]+/events", "/challenges/not-a-uuid/events"));

        try (SseClient stream = new SseClient(malformed)) {
            assertEquals(400, stream.awaitStatusCode(RESPONSE_TIMEOUT));
        }
    }

    private void assertSingleTerminalEvent(URI uri, String expectedStatus) throws Exception {
        try (SseClient stream = new SseClient(uri)) {
            assertEquals(200, stream.awaitStatusCode(RESPONSE_TIMEOUT));
            assertSseHeaders(stream);
            List<SseClient.Event> items = stream.awaitEnd(RESPONSE_TIMEOUT);
            assertEquals(1, items.size(), "Expected exactly one event: " + items);
            assertEquals("status", items.getFirst().name());
            assertEquals(expectedStatus, items.getFirst().status());
        }
    }

    private void assertConnectionSlotIsReleased(URI eventsUri) throws Exception {
        long deadline =
                System.nanoTime() + Duration.ofSeconds(HEARTBEAT_SECONDS * 3L).toNanos();
        String lastStatus = null;
        while (System.nanoTime() < deadline) {
            try (SseClient stream = new SseClient(eventsUri)) {
                SseClient.Event event = stream.awaitEvent(RESPONSE_TIMEOUT);
                lastStatus = event != null ? event.status() : null;
                if ("PENDING".equals(lastStatus)) {
                    return;
                }
            }
            Thread.sleep(500);
        }
        throw new AssertionError("Connection slots not released after close, last status " + lastStatus);
    }

    private static void assertSseHeaders(SseClient stream) throws Exception {
        String contentType = stream.awaitHeader("Content-Type", RESPONSE_TIMEOUT);
        assertTrue(contentType.startsWith("text/event-stream"), "Unexpected content type: " + contentType);
        assertEquals("no-store", stream.awaitHeader("Cache-Control", RESPONSE_TIMEOUT));
        assertEquals("no-cache", stream.awaitHeader("Pragma", RESPONSE_TIMEOUT));
        assertEquals("no", stream.awaitHeader("X-Accel-Buffering", RESPONSE_TIMEOUT));
    }

    private int wellKnownStatus() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(baseUri.resolve("realms/demo/.well-known/openid-configuration"))
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();
        return HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.discarding())
                .statusCode();
    }

    private URI enrollmentEventsUri(String username) throws Exception {
        adminClient.ensureUser(username, PASSWORD);
        adminClient.resetUserState(username);
        BrowserSession session = new BrowserSession(baseUri);
        HtmlPage loginPage = session.startAuthorization("test-app");
        HtmlPage enrollPage = session.submitLogin(loginPage, username, PASSWORD);
        return session.extractEnrollmentEventsUri(enrollPage);
    }

    private static URI withQuery(URI uri, String query) throws Exception {
        return new URI(uri.getScheme(), uri.getAuthority(), uri.getPath(), query, null);
    }
}
