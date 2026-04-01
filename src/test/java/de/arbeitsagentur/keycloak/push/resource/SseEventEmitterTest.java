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
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import jakarta.ws.rs.core.GenericType;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.sse.OutboundSseEvent;
import jakarta.ws.rs.sse.Sse;
import jakarta.ws.rs.sse.SseBroadcaster;
import jakarta.ws.rs.sse.SseEventSink;
import java.lang.reflect.Type;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import org.junit.jupiter.api.Test;

class SseEventEmitterTest {

    @Test
    void statusEventSetsReconnectDelayOnlyWhenExplicitlyRequested() {
        SseEventEmitter emitter = new SseEventEmitter();
        TestSink sink = new TestSink();
        PushChallenge challenge = challenge(PushChallengeStatus.PENDING);

        assertTrue(emitter.sendStatusEvent(sink, new TestSse(), "PENDING", challenge, SseEventEmitter.EventType.LOGIN)
                .toCompletableFuture()
                .join());
        assertFalse(sink.events().get(0).isReconnectDelaySet());

        assertTrue(emitter.sendStatusEvent(
                        sink, new TestSse(), "TOO_MANY_CONNECTIONS", null, SseEventEmitter.EventType.LOGIN, 1500L)
                .toCompletableFuture()
                .join());
        assertTrue(sink.events().get(1).isReconnectDelaySet());
        assertEquals(1500L, sink.events().get(1).getReconnectDelay());
    }

    @Test
    void heartbeatDoesNotSetReconnectDelay() {
        SseEventEmitter emitter = new SseEventEmitter();
        TestSink sink = new TestSink();

        assertTrue(
                emitter.sendHeartbeat(sink, new TestSse()).toCompletableFuture().join());
        assertFalse(sink.events().getFirst().isReconnectDelaySet());
        assertEquals("keepalive", sink.events().getFirst().getComment());
    }

    private static PushChallenge challenge(PushChallengeStatus status) {
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
                status,
                now,
                status == PushChallengeStatus.PENDING ? null : now,
                PushChallenge.UserVerificationMode.NONE,
                null,
                List.of());
    }

    private static final class TestSink implements SseEventSink {
        private final List<OutboundSseEvent> events = new ArrayList<>();
        private boolean closed;

        @Override
        public boolean isClosed() {
            return closed;
        }

        @Override
        public CompletionStage<?> send(OutboundSseEvent event) {
            events.add(event);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public void close() {
            closed = true;
        }

        private List<OutboundSseEvent> events() {
            return events;
        }
    }

    private static final class TestSse implements Sse {
        @Override
        public OutboundSseEvent.Builder newEventBuilder() {
            return new TestEventBuilder();
        }

        @Override
        public SseBroadcaster newBroadcaster() {
            throw new UnsupportedOperationException();
        }
    }

    private static final class TestEventBuilder implements OutboundSseEvent.Builder {
        private String id;
        private String name;
        private String comment;
        private long reconnectDelay;
        private boolean reconnectDelaySet;
        private Class<?> type;
        private Type genericType;
        private MediaType mediaType;
        private Object data;

        @Override
        public OutboundSseEvent.Builder id(String id) {
            this.id = id;
            return this;
        }

        @Override
        public OutboundSseEvent.Builder name(String name) {
            this.name = name;
            return this;
        }

        @Override
        public OutboundSseEvent.Builder reconnectDelay(long milliseconds) {
            this.reconnectDelay = milliseconds;
            this.reconnectDelaySet = true;
            return this;
        }

        @Override
        public OutboundSseEvent.Builder mediaType(MediaType mediaType) {
            this.mediaType = mediaType;
            return this;
        }

        @Override
        public OutboundSseEvent.Builder comment(String comment) {
            this.comment = comment;
            return this;
        }

        @Override
        public OutboundSseEvent.Builder data(Class type, Object data) {
            this.type = type;
            this.genericType = type;
            this.data = data;
            return this;
        }

        @Override
        public OutboundSseEvent.Builder data(GenericType type, Object data) {
            this.type = type.getRawType();
            this.genericType = type.getType();
            this.data = data;
            return this;
        }

        @Override
        public OutboundSseEvent.Builder data(Object data) {
            this.type = data != null ? data.getClass() : Object.class;
            this.genericType = this.type;
            this.data = data;
            return this;
        }

        @Override
        public OutboundSseEvent build() {
            return new TestOutboundSseEvent(
                    id, name, comment, reconnectDelay, reconnectDelaySet, type, genericType, mediaType, data);
        }
    }

    private record TestOutboundSseEvent(
            String id,
            String name,
            String comment,
            long reconnectDelay,
            boolean reconnectDelaySet,
            Class<?> type,
            Type genericType,
            MediaType mediaType,
            Object data)
            implements OutboundSseEvent {

        @Override
        public String getId() {
            return id;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public String getComment() {
            return comment;
        }

        @Override
        public long getReconnectDelay() {
            return reconnectDelay;
        }

        @Override
        public boolean isReconnectDelaySet() {
            return reconnectDelaySet;
        }

        @Override
        public Class<?> getType() {
            return type;
        }

        @Override
        public Type getGenericType() {
            return genericType;
        }

        @Override
        public MediaType getMediaType() {
            return mediaType;
        }

        @Override
        public Object getData() {
            return data;
        }
    }
}
