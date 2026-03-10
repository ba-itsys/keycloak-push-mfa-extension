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
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;

public final class SseClient implements AutoCloseable {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final BlockingQueue<String> statuses = new LinkedBlockingQueue<>();
    private final CompletableFuture<HttpResponse<InputStream>> responseFuture;
    private final CompletableFuture<Void> readerFuture;

    public SseClient(URI eventsUri) {
        HttpClient http =
                HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
        HttpRequest request = HttpRequest.newBuilder(eventsUri)
                .header("Accept", "text/event-stream")
                .GET()
                .build();
        this.responseFuture = http.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream());
        this.readerFuture = responseFuture.thenAcceptAsync(response -> readEvents(response.body()));
    }

    public int awaitStatusCode(Duration timeout) throws Exception {
        return responseFuture
                .get(timeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS)
                .statusCode();
    }

    public String awaitStatus(Duration timeout) throws Exception {
        return statuses.poll(timeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
    }

    private void readEvents(InputStream stream) {
        try (InputStream input = stream;
                BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String eventName = null;
            List<String> dataLines = new ArrayList<>();
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty()) {
                    emitEvent(eventName, dataLines);
                    eventName = null;
                    dataLines.clear();
                    continue;
                }
                if (line.startsWith(":")) {
                    continue;
                }
                if (line.startsWith("event:")) {
                    eventName = line.substring("event:".length()).trim();
                    continue;
                }
                if (line.startsWith("data:")) {
                    dataLines.add(line.substring("data:".length()).trim());
                }
            }
            emitEvent(eventName, dataLines);
        } catch (Exception ignored) {
            // Closing the client terminates the stream and ends the reader.
        }
    }

    private void emitEvent(String eventName, List<String> dataLines) throws Exception {
        if (!"status".equals(eventName) || dataLines.isEmpty()) {
            return;
        }
        JsonNode payload = MAPPER.readTree(String.join("\n", dataLines));
        String status = payload.path("status").asText(null);
        if (status != null) {
            statuses.offer(status);
        }
    }

    @Override
    public void close() {
        responseFuture
                .thenAccept(response -> {
                    try {
                        response.body().close();
                    } catch (Exception ignored) {
                        // no-op
                    }
                })
                .cancel(true);
        readerFuture.cancel(true);
    }
}
