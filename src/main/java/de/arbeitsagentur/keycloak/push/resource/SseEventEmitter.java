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

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import jakarta.ws.rs.sse.OutboundSseEvent;
import jakarta.ws.rs.sse.Sse;
import jakarta.ws.rs.sse.SseEventSink;
import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import org.keycloak.util.JsonSerialization;

/**
 * Writes challenge status events to one SSE connection. Sends block until the event is written and throw
 * {@link IOException} if the connection is closed, fails or stalls.
 */
public final class SseEventEmitter {

    public enum EventType {
        LOGIN,
        ENROLLMENT
    }

    // Limits how long a send waits for a client that stopped reading.
    private static final Duration DEFAULT_SEND_TIMEOUT = Duration.ofSeconds(30);

    private final SseEventSink sink;
    private final Sse sse;
    private final Duration sendTimeout;
    private final AtomicBoolean closed = new AtomicBoolean();

    public SseEventEmitter(SseEventSink sink, Sse sse) {
        this(sink, sse, DEFAULT_SEND_TIMEOUT);
    }

    SseEventEmitter(SseEventSink sink, Sse sse, Duration sendTimeout) {
        this.sink = Objects.requireNonNull(sink, "sink");
        this.sse = Objects.requireNonNull(sse, "sse");
        this.sendTimeout = Objects.requireNonNull(sendTimeout, "sendTimeout");
    }

    public void sendStatusEvent(String status) throws IOException {
        sendStatusEvent(payloadForStatus(status), null);
    }

    public void sendStatusEvent(String status, PushChallenge challenge, EventType type) throws IOException {
        sendStatusEvent(payloadForStatus(status, challenge, type), null);
    }

    public void sendRetryStatusEvent(String status, PushChallenge challenge, EventType type, long retryAfterMillis)
            throws IOException {
        Map<String, Object> payload = payloadForStatus(status, challenge, type);
        payload.put("retryAfterMillis", retryAfterMillis);
        sendStatusEvent(payload, retryAfterMillis);
    }

    public void sendHeartbeat() throws IOException {
        send(sse.newEventBuilder().comment("keepalive").build());
    }

    // True once the client disconnected or close() was called.
    public boolean isClosed() {
        return closed.get() || sink.isClosed();
    }

    // Closes the connection. Further calls do nothing.
    public void close() {
        if (closed.compareAndSet(false, true)) {
            sink.close();
        }
    }

    private void sendStatusEvent(Map<String, Object> payload, Long retryAfterMillis) throws IOException {
        OutboundSseEvent.Builder builder =
                sse.newEventBuilder().name("status").data(String.class, JsonSerialization.writeValueAsString(payload));
        if (retryAfterMillis != null) {
            builder.reconnectDelay(retryAfterMillis);
        }
        send(builder.build());
    }

    private void send(OutboundSseEvent event) throws IOException {
        if (sink.isClosed()) {
            throw new IOException("SSE connection is closed");
        }
        try {
            sink.send(event).toCompletableFuture().get(sendTimeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (ExecutionException ex) {
            throw new IOException("Unable to send SSE event", ex.getCause());
        } catch (TimeoutException ex) {
            throw new IOException("Timed out after " + sendTimeout + " sending SSE event", ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while sending SSE event", ex);
        } catch (IllegalStateException ex) {
            // The sink throws this if the connection closed after the isClosed() check.
            throw new IOException("SSE connection is closed", ex);
        }
    }

    private Map<String, Object> payloadForStatus(String status) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("status", status);
        return payload;
    }

    private Map<String, Object> payloadForStatus(String status, PushChallenge challenge, EventType type) {
        Map<String, Object> payload = payloadForStatus(status);
        payload.put("challengeId", challenge.getId());
        payload.put("expiresAt", challenge.getExpiresAt().toString());
        if (type == EventType.LOGIN) {
            payload.put("clientId", challenge.getClientId());
        }
        return payload;
    }
}
