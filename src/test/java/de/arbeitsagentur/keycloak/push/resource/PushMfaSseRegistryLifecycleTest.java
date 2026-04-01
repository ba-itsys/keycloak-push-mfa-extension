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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;

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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class PushMfaSseRegistryLifecycleTest {

    private static final String CHALLENGE_ID = "challenge-1";
    private static final String SECRET = "watch-secret";
    private static final String REALM_ID = "realm-1";
    private static final String ROOT_SESSION_ID = "root-session-1";

    @Test
    void pollsEachChallengeOnlyOnceForMultipleWatchers() {
        AtomicInteger reads = new AtomicInteger();
        PushMfaSseRegistry registry = registry(
                request -> {
                    reads.incrementAndGet();
                    return PushMfaSseRegistry.ChallengeReadResult.success(
                            authenticationChallenge(ROOT_SESSION_ID, PushChallengeStatus.PENDING));
                },
                5000,
                60000,
                4);

        TestSink firstSink = new TestSink();
        TestSink secondSink = new TestSink();

        assertTrue(registry.register(
                CHALLENGE_ID,
                SECRET,
                firstSink,
                new TestSse(),
                SseEventEmitter.EventType.LOGIN,
                PushChallenge.Type.AUTHENTICATION,
                null));
        assertTrue(registry.register(
                CHALLENGE_ID,
                SECRET,
                secondSink,
                new TestSse(),
                SseEventEmitter.EventType.LOGIN,
                PushChallenge.Type.AUTHENTICATION,
                null));

        registry.pollOnce();

        assertEquals(1, reads.get());
        assertEquals(1, firstSink.events().size());
        assertEquals(1, secondSink.events().size());
        assertTrue(String.valueOf(firstSink.events().getFirst().getData()).contains("\"status\":\"PENDING\""));
        assertTrue(String.valueOf(secondSink.events().getFirst().getData()).contains("\"status\":\"PENDING\""));
    }

    @Test
    void rejectsWatcherWhenMaxConnectionsIsReached() {
        PushMfaSseRegistry registry = registry(
                request -> PushMfaSseRegistry.ChallengeReadResult.success(
                        authenticationChallenge(ROOT_SESSION_ID, PushChallengeStatus.PENDING)),
                5000,
                60000,
                1);

        assertTrue(registry.register(
                CHALLENGE_ID,
                SECRET,
                new TestSink(),
                new TestSse(),
                SseEventEmitter.EventType.LOGIN,
                PushChallenge.Type.AUTHENTICATION,
                null));
        assertFalse(registry.register(
                "challenge-2",
                SECRET,
                new TestSink(),
                new TestSse(),
                SseEventEmitter.EventType.LOGIN,
                PushChallenge.Type.AUTHENTICATION,
                null));
    }

    @Test
    void terminalStatusClosesOnlyAfterAsyncSendCompletes() {
        CompletableFuture<Void> sendFuture = new CompletableFuture<>();
        PushMfaSseRegistry registry = registry(
                request -> PushMfaSseRegistry.ChallengeReadResult.success(
                        authenticationChallenge(ROOT_SESSION_ID, PushChallengeStatus.APPROVED)),
                5000,
                60000,
                1);
        TestSink sink = new TestSink(event -> sendFuture);

        assertTrue(registry.register(
                CHALLENGE_ID,
                SECRET,
                sink,
                new TestSse(),
                SseEventEmitter.EventType.LOGIN,
                PushChallenge.Type.AUTHENTICATION,
                null));

        registry.pollOnce();

        assertFalse(sink.isClosed());
        assertFalse(registry.register(
                "challenge-2",
                SECRET,
                new TestSink(),
                new TestSse(),
                SseEventEmitter.EventType.LOGIN,
                PushChallenge.Type.AUTHENTICATION,
                null));

        sendFuture.complete(null);

        assertTrue(sink.isClosed());
        assertTrue(registry.register(
                "challenge-2",
                SECRET,
                new TestSink(),
                new TestSse(),
                SseEventEmitter.EventType.LOGIN,
                PushChallenge.Type.AUTHENTICATION,
                null));
    }

    @Test
    void sendsHeartbeatForIdlePendingWatcher() throws Exception {
        PushMfaSseRegistry registry = registry(
                request -> PushMfaSseRegistry.ChallengeReadResult.success(
                        authenticationChallenge(ROOT_SESSION_ID, PushChallengeStatus.PENDING)),
                5,
                60000,
                2);
        TestSink sink = new TestSink();

        assertTrue(registry.register(
                CHALLENGE_ID,
                SECRET,
                sink,
                new TestSse(),
                SseEventEmitter.EventType.LOGIN,
                PushChallenge.Type.AUTHENTICATION,
                PushChallengeStatus.PENDING));

        Thread.sleep(10);
        registry.pollOnce();

        assertEquals(1, sink.events().size());
        assertEquals("keepalive", sink.events().getFirst().getComment());
        assertFalse(sink.events().getFirst().isReconnectDelaySet());
    }

    @Test
    void closesOldConnectionsToForceReconnect() throws Exception {
        PushMfaSseRegistry registry = registry(
                request -> PushMfaSseRegistry.ChallengeReadResult.success(
                        authenticationChallenge(ROOT_SESSION_ID, PushChallengeStatus.PENDING)),
                5000,
                1,
                1);
        TestSink sink = new TestSink();

        assertTrue(registry.register(
                CHALLENGE_ID,
                SECRET,
                sink,
                new TestSse(),
                SseEventEmitter.EventType.LOGIN,
                PushChallenge.Type.AUTHENTICATION,
                PushChallengeStatus.PENDING));

        Thread.sleep(5);
        registry.pollOnce();

        assertTrue(sink.isClosed());
        assertTrue(registry.register(
                "challenge-2",
                SECRET,
                new TestSink(),
                new TestSse(),
                SseEventEmitter.EventType.LOGIN,
                PushChallenge.Type.AUTHENTICATION,
                null));
    }

    private PushMfaSseRegistry registry(
            Function<PushMfaSseRegistry.ChallengeReadRequest, PushMfaSseRegistry.ChallengeReadResult> reader,
            long heartbeatIntervalMillis,
            long maxConnectionLifetimeMillis,
            int maxConnections) {
        ExecutorService executor = mock(ExecutorService.class);
        doNothing().when(executor).execute(any(Runnable.class));
        return new PushMfaSseRegistry(
                maxConnections,
                heartbeatIntervalMillis,
                maxConnectionLifetimeMillis,
                reader,
                new SseEventEmitter(),
                executor);
    }

    private PushChallenge authenticationChallenge(String rootSessionId, PushChallengeStatus status) {
        Instant now = Instant.now();
        return new PushChallenge(
                CHALLENGE_ID,
                REALM_ID,
                "user-1",
                new byte[0],
                "credential-1",
                "client-1",
                SECRET,
                rootSessionId,
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
        private final Function<OutboundSseEvent, CompletionStage<?>> sender;
        private final List<OutboundSseEvent> events = new ArrayList<>();
        private volatile boolean closed;

        private TestSink() {
            this(event -> CompletableFuture.completedFuture(null));
        }

        private TestSink(Function<OutboundSseEvent, CompletionStage<?>> sender) {
            this.sender = sender;
        }

        @Override
        public boolean isClosed() {
            return closed;
        }

        @Override
        public CompletionStage<?> send(OutboundSseEvent event) {
            events.add(event);
            return sender.apply(event);
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
