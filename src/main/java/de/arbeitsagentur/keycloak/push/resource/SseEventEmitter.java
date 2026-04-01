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
import jakarta.ws.rs.sse.Sse;
import jakarta.ws.rs.sse.SseEventSink;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import org.jboss.logging.Logger;
import org.keycloak.util.JsonSerialization;

/** Helper for emitting SSE events for enrollment and login challenges. */
public final class SseEventEmitter {

    private static final Logger LOG = Logger.getLogger(SseEventEmitter.class);

    public enum EventType {
        LOGIN,
        ENROLLMENT
    }

    public CompletionStage<Boolean> sendStatusEvent(
            SseEventSink sink, Sse sse, String status, PushChallenge challenge, EventType type) {
        return sendStatusEvent(sink, sse, status, challenge, type, null);
    }

    public CompletionStage<Boolean> sendStatusEvent(
            SseEventSink sink, Sse sse, String status, PushChallenge challenge, EventType type, Long retryAfterMillis) {
        if (sink.isClosed()) {
            return CompletableFuture.completedFuture(false);
        }
        try {
            String targetChallengeId = challenge != null ? challenge.getId() : "n/a";
            String typeLabel = type == EventType.LOGIN ? "login" : "enrollment";
            LOG.debugf("Emitting %s SSE status %s for challenge %s", typeLabel, status, targetChallengeId);

            Map<String, Object> payload = new HashMap<>();
            payload.put("status", status);
            if (retryAfterMillis != null) {
                payload.put("retryAfterMillis", retryAfterMillis);
            }
            if (challenge != null) {
                payload.put("challengeId", challenge.getId());
                payload.put("expiresAt", challenge.getExpiresAt().toString());
                if (type == EventType.LOGIN) {
                    payload.put("clientId", challenge.getClientId());
                }
                if (challenge.getResolvedAt() != null) {
                    payload.put("resolvedAt", challenge.getResolvedAt().toString());
                }
            }
            String data = JsonSerialization.writeValueAsString(payload);
            var builder = sse.newEventBuilder().name("status").data(String.class, data);
            if (retryAfterMillis != null) {
                builder.reconnectDelay(retryAfterMillis);
            }
            return sink.send(builder.build()).handle((ignored, ex) -> {
                if (ex != null) {
                    LOG.warnf(
                            ex,
                            "Unable to send %s SSE status %s for %s",
                            typeLabel,
                            status,
                            challenge != null ? challenge.getId() : "n/a");
                    return false;
                }
                return true;
            });
        } catch (Exception ex) {
            String typeLabel = type == EventType.LOGIN ? "login" : "enrollment";
            LOG.warnf(
                    ex,
                    "Unable to send %s SSE status %s for %s",
                    typeLabel,
                    status,
                    challenge != null ? challenge.getId() : "n/a");
            return CompletableFuture.completedFuture(false);
        }
    }

    public CompletionStage<Boolean> sendHeartbeat(SseEventSink sink, Sse sse) {
        if (sink.isClosed()) {
            return CompletableFuture.completedFuture(false);
        }
        try {
            LOG.debug("Emitting SSE heartbeat");
            return sink.send(sse.newEventBuilder().comment("keepalive").build()).handle((ignored, ex) -> {
                if (ex != null) {
                    LOG.warn("Unable to send SSE heartbeat", ex);
                    return false;
                }
                return true;
            });
        } catch (Exception ex) {
            LOG.warn("Unable to send SSE heartbeat", ex);
            return CompletableFuture.completedFuture(false);
        }
    }
}
