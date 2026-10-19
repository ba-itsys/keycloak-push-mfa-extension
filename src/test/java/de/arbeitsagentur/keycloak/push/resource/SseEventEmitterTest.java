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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import jakarta.ws.rs.sse.OutboundSseEvent;
import jakarta.ws.rs.sse.Sse;
import jakarta.ws.rs.sse.SseEventSink;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;
import org.mockito.ArgumentCaptor;

class SseEventEmitterTest {

    private final SseEventSink sink = mock(SseEventSink.class);
    private final OutboundSseEvent.Builder builder = mock(OutboundSseEvent.Builder.class, RETURNS_SELF);
    private final OutboundSseEvent event = mock(OutboundSseEvent.class);
    private SseEventEmitter emitter;

    @BeforeEach
    void setUp() {
        Sse sse = mock(Sse.class);
        when(sse.newEventBuilder()).thenReturn(builder);
        when(builder.build()).thenReturn(event);
        when(sink.send(event)).thenAnswer(invocation -> CompletableFuture.completedFuture(null));
        emitter = new SseEventEmitter(sink, sse, Duration.ofMillis(50));
    }

    @Test
    void loginStatusEventCarriesChallengeDetailsWithoutRetry() throws Exception {
        emitter.sendStatusEvent("PENDING", challenge(), SseEventEmitter.EventType.LOGIN);

        verify(builder).name("status");
        verify(builder, never()).reconnectDelay(anyLong());
        verify(sink).send(event);
        JsonNode payload = sentPayload();
        assertEquals("PENDING", payload.get("status").asText());
        assertEquals("challenge-1", payload.get("challengeId").asText());
        assertEquals("client-1", payload.get("clientId").asText());
        assertTrue(payload.hasNonNull("expiresAt"));
        assertFalse(payload.has("retryAfterMillis"));
    }

    @Test
    void enrollmentStatusEventOmitsClientId() throws Exception {
        emitter.sendStatusEvent("APPROVED", challenge(), SseEventEmitter.EventType.ENROLLMENT);

        assertFalse(sentPayload().has("clientId"));
    }

    @Test
    void statusOnlyEventCarriesOnlyTheStatus() throws Exception {
        emitter.sendStatusEvent("INVALID");

        JsonNode payload = sentPayload();
        assertEquals(1, payload.size());
        assertEquals("INVALID", payload.get("status").asText());
    }

    @Test
    void retryStatusEventSetsReconnectDelayAndPayloadHint() throws Exception {
        emitter.sendRetryStatusEvent("TOO_MANY_CONNECTIONS", challenge(), SseEventEmitter.EventType.LOGIN, 1500L);

        verify(builder).reconnectDelay(1500L);
        JsonNode payload = sentPayload();
        assertEquals("TOO_MANY_CONNECTIONS", payload.get("status").asText());
        assertEquals(1500L, payload.get("retryAfterMillis").asLong());
    }

    @Test
    void heartbeatIsCommentOnly() throws Exception {
        emitter.sendHeartbeat();

        verify(builder).comment("keepalive");
        verify(builder, never()).name(anyString());
        verify(builder, never()).data(any(Class.class), any());
        verify(sink).send(event);
    }

    @Test
    void sendingToClosedSinkFailsWithoutSending() {
        when(sink.isClosed()).thenReturn(true);

        assertThrows(IOException.class, emitter::sendHeartbeat);
        verify(sink, never()).send(any());
    }

    @Test
    void failedSendIsReportedAsIoExceptionWithCause() {
        IllegalStateException failure = new IllegalStateException("connection reset");
        when(sink.send(event)).thenAnswer(invocation -> CompletableFuture.failedFuture(failure));

        IOException thrown = assertThrows(IOException.class, emitter::sendHeartbeat);

        assertSame(failure, thrown.getCause());
    }

    @Test
    void sendRejectedBySinkIsReportedAsIoException() {
        IllegalStateException rejected = new IllegalStateException("closed");
        when(sink.send(event)).thenThrow(rejected);

        IOException thrown = assertThrows(IOException.class, emitter::sendHeartbeat);

        assertSame(rejected, thrown.getCause());
    }

    @Test
    void stalledSendTimesOut() {
        when(sink.send(event)).thenAnswer(invocation -> new CompletableFuture<>());

        IOException thrown = assertThrows(IOException.class, emitter::sendHeartbeat);

        assertInstanceOf(TimeoutException.class, thrown.getCause());
    }

    @Test
    void isClosedFollowsSink() {
        assertFalse(emitter.isClosed());
        when(sink.isClosed()).thenReturn(true);
        assertTrue(emitter.isClosed());
    }

    @Test
    void closeClosesSinkOnce() {
        emitter.close();
        emitter.close();

        verify(sink, times(1)).close();
        assertTrue(emitter.isClosed());
    }

    private JsonNode sentPayload() throws IOException {
        ArgumentCaptor<Object> data = ArgumentCaptor.forClass(Object.class);
        verify(builder).data(eq(String.class), data.capture());
        return JsonSerialization.mapper.readTree((String) data.getValue());
    }

    private static PushChallenge challenge() {
        Instant now = Instant.now();
        return new PushChallenge(
                "challenge-1",
                "realm-1",
                "user-1",
                new byte[0],
                "credential-1",
                "client-1",
                "watch-secret",
                "root-session-1",
                now.plusSeconds(60),
                PushChallenge.Type.AUTHENTICATION,
                PushChallengeStatus.PENDING,
                now,
                null,
                PushChallenge.UserVerificationMode.NONE,
                null,
                List.of());
    }
}
