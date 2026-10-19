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

package de.arbeitsagentur.keycloak.push.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.glassfish.jersey.media.sse.EventInput;
import org.glassfish.jersey.media.sse.InboundEvent;

// Reads one SSE connection with the Jersey SSE client. Does not reconnect.
public final class SseClient implements AutoCloseable {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // Each open stream blocks its reader thread. The common pool has too few threads for that on small machines.
    private static final ExecutorService READERS = Executors.newVirtualThreadPerTaskExecutor();

    // A received event. Heartbeats arrive as events with only a comment.
    public record Event(String name, String data, String comment, Long retry) {

        public boolean isComment() {
            return name == null && data == null && comment != null;
        }

        public JsonNode json() throws IOException {
            return MAPPER.readTree(data);
        }

        public String status() throws IOException {
            return json().path("status").asText(null);
        }
    }

    // Queued when the stream ends. Compared by identity.
    private static final Event END = new Event(null, null, null, null);

    private final Client client = ClientBuilder.newClient();
    private final BlockingQueue<Event> events = new LinkedBlockingQueue<>();
    private final CompletableFuture<Response> response;
    private volatile EventInput input;

    public SseClient(URI eventsUri) {
        this.response = CompletableFuture.supplyAsync(
                () -> client.target(eventsUri)
                        .request(MediaType.SERVER_SENT_EVENTS_TYPE)
                        .get(),
                READERS);
        response.thenAcceptAsync(this::readEvents, READERS);
    }

    public int awaitStatusCode(Duration timeout) throws Exception {
        return awaitResponse(timeout).getStatus();
    }

    public String awaitHeader(String name, Duration timeout) throws Exception {
        return awaitResponse(timeout).getHeaderString(name);
    }

    // Returns the status of the next "status" event, or null on timeout or end of stream.
    public String awaitStatus(Duration timeout) throws Exception {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            Event event = awaitEvent(Duration.ofNanos(Math.max(0, deadline - System.nanoTime())));
            if (event == null) {
                return null;
            }
            if ("status".equals(event.name())) {
                return event.status();
            }
        }
    }

    // Returns the next event including heartbeats, or null on timeout or end of stream.
    public Event awaitEvent(Duration timeout) throws InterruptedException {
        Event event = events.poll(timeout.toNanos(), TimeUnit.NANOSECONDS);
        if (event == END) {
            events.offer(END);
            return null;
        }
        return event;
    }

    // Waits for the server to close the stream and returns the events received until then.
    public List<Event> awaitEnd(Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        List<Event> received = new ArrayList<>();
        while (true) {
            long remaining = deadline - System.nanoTime();
            Event event = remaining > 0 ? events.poll(remaining, TimeUnit.NANOSECONDS) : null;
            if (event == null) {
                throw new AssertionError("SSE stream did not end within " + timeout + ", received " + received);
            }
            if (event == END) {
                events.offer(END);
                return received;
            }
            received.add(event);
        }
    }

    private Response awaitResponse(Duration timeout) throws Exception {
        return response.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
    }

    private void readEvents(Response streamResponse) {
        try {
            if (streamResponse.getStatus() != 200) {
                return;
            }
            try (EventInput eventInput = streamResponse.readEntity(EventInput.class)) {
                input = eventInput;
                InboundEvent event;
                while ((event = eventInput.read()) != null) {
                    events.offer(toEvent(event));
                }
            }
        } catch (RuntimeException ignored) {
            // close() ends a blocked read with an exception
        } finally {
            events.offer(END);
        }
    }

    private static Event toEvent(InboundEvent event) {
        return new Event(
                event.getName(),
                event.isEmpty() ? null : event.readData(String.class),
                event.getComment(),
                event.isReconnectDelaySet() ? event.getReconnectDelay() : null);
    }

    @Override
    public void close() {
        EventInput eventInput = input;
        if (eventInput != null) {
            eventInput.close();
        }
        client.close();
    }
}
