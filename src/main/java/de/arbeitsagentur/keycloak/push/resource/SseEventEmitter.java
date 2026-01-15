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
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import jakarta.ws.rs.sse.Sse;
import jakarta.ws.rs.sse.SseEventSink;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/** Helper for emitting SSE events for enrollment and login challenges. */
public final class SseEventEmitter {

    private static final Logger LOG = Logger.getLogger(SseEventEmitter.class);

    public enum EventType {
        LOGIN,
        ENROLLMENT
    }

    private final PushChallengeStore challengeStore;

    public SseEventEmitter(PushChallengeStore challengeStore) {
        this.challengeStore = challengeStore;
    }

    public void emitEvents(
            String challengeId,
            String secret,
            SseEventSink sink,
            Sse sse,
            EventType type,
            PushChallenge.Type expectedType) {
        String typeLabel = type == EventType.LOGIN ? "login" : "enrollment";
        try (SseEventSink eventSink = sink) {
            LOG.infof("Starting %s SSE stream for challenge %s", typeLabel, challengeId);
            if (StringUtil.isBlank(secret)) {
                LOG.infof("%s SSE rejected for %s due to missing secret", capitalize(typeLabel), challengeId);
                sendStatusEvent(eventSink, sse, "INVALID", null, type);
                return;
            }

            PushChallengeStatus lastStatus = null;
            while (!eventSink.isClosed()) {
                Optional<PushChallenge> challengeOpt = challengeStore.get(challengeId);
                if (challengeOpt.isEmpty()) {
                    LOG.infof("%s SSE challenge %s not found", capitalize(typeLabel), challengeId);
                    sendStatusEvent(eventSink, sse, "NOT_FOUND", null, type);
                    break;
                }
                PushChallenge challenge = challengeOpt.get();

                if (expectedType != null && challenge.getType() != expectedType) {
                    LOG.infof(
                            "%s SSE rejected for %s because challenge type is %s",
                            capitalize(typeLabel), challengeId, challenge.getType());
                    sendStatusEvent(eventSink, sse, "BAD_TYPE", null, type);
                    break;
                }

                if (!Objects.equals(secret, challenge.getWatchSecret())) {
                    LOG.infof("%s SSE forbidden for %s due to secret mismatch", capitalize(typeLabel), challengeId);
                    sendStatusEvent(eventSink, sse, "FORBIDDEN", null, type);
                    break;
                }

                PushChallengeStatus currentStatus = challenge.getStatus();
                if (lastStatus != currentStatus) {
                    sendStatusEvent(eventSink, sse, currentStatus.name(), challenge, type);
                    lastStatus = currentStatus;
                }

                if (currentStatus != PushChallengeStatus.PENDING) {
                    LOG.infof(
                            "%s SSE exiting for %s after reaching status %s",
                            capitalize(typeLabel), challengeId, currentStatus);
                    break;
                }

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    sendStatusEvent(eventSink, sse, "INTERRUPTED", null, type);
                    LOG.infof("%s SSE interrupted for %s", capitalize(typeLabel), challengeId);
                    break;
                }
            }
            LOG.infof("%s SSE stream closed for challenge %s", capitalize(typeLabel), challengeId);
        } catch (Exception ex) {
            LOG.infof(ex, "Failed to stream %s events for %s", typeLabel, challengeId);
        }
    }

    public void sendStatusEvent(SseEventSink sink, Sse sse, String status, PushChallenge challenge, EventType type) {
        if (sink.isClosed()) {
            return;
        }
        try {
            String targetChallengeId = challenge != null ? challenge.getId() : "n/a";
            String typeLabel = type == EventType.LOGIN ? "login" : "enrollment";
            LOG.infof("Emitting %s SSE status %s for challenge %s", typeLabel, status, targetChallengeId);

            Map<String, Object> payload = new HashMap<>();
            payload.put("status", status);
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
            sink.send(sse.newEventBuilder()
                    .name("status")
                    .data(String.class, data)
                    .build());
        } catch (Exception ex) {
            String typeLabel = type == EventType.LOGIN ? "login" : "enrollment";
            LOG.infof(
                    ex,
                    "Unable to send %s SSE status %s for %s",
                    typeLabel,
                    status,
                    challenge != null ? challenge.getId() : "n/a");
        }
    }

    private static String capitalize(String s) {
        if (s == null || s.isEmpty()) return s;
        return Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }
}
