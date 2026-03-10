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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.KeycloakModelUtils;

final class PushMfaSseRegistry {

    private static final Logger LOG = Logger.getLogger(PushMfaSseRegistry.class);
    private static final long POLL_INTERVAL_MILLIS = 1000L;

    interface ChallengeReader {
        ChallengeReadResult read(String challengeId, String secret, PushChallenge.Type expectedType);
    }

    private final int maxConnections;
    private final Semaphore permits;
    private final Executor executor;
    private final ChallengeReader challengeReader;
    private final SseEventEmitter emitter;
    private final AtomicBoolean pollerStarted = new AtomicBoolean();
    private final Map<String, Registration> registrations = new HashMap<>();

    PushMfaSseRegistry(int maxConnections, KeycloakSessionFactory sessionFactory, ExecutorService executor) {
        this(maxConnections, createChallengeReader(sessionFactory), new SseEventEmitter(), executor);
    }

    PushMfaSseRegistry(
            int maxConnections, ChallengeReader challengeReader, SseEventEmitter emitter, ExecutorService executor) {
        this.maxConnections = maxConnections;
        this.permits = new Semaphore(maxConnections);
        this.challengeReader = Objects.requireNonNull(challengeReader);
        this.emitter = Objects.requireNonNull(emitter);
        this.executor = Objects.requireNonNullElseGet(executor, PushMfaSseRegistry::createExecutor);
    }

    int maxConnections() {
        return maxConnections;
    }

    ChallengeReadResult readChallenge(String challengeId, String secret, PushChallenge.Type expectedType) {
        return challengeReader.read(challengeId, secret, expectedType);
    }

    boolean register(
            String challengeId,
            String secret,
            SseEventSink sink,
            Sse sse,
            SseEventEmitter.EventType type,
            PushChallenge.Type expectedType,
            PushChallengeStatus lastStatus) {
        if (!permits.tryAcquire()) {
            return false;
        }

        Registration registration = new Registration(
                UUID.randomUUID().toString(), challengeId, secret, sink, sse, type, expectedType, lastStatus);

        synchronized (registrations) {
            registrations.put(registration.id(), registration);
        }

        if (!startPoller()) {
            unregister(registration, true);
            return false;
        }

        return true;
    }

    void pollOnce() {
        for (Registration registration : snapshotRegistrations()) {
            if (registration.sink().isClosed()) {
                unregister(registration, false);
                continue;
            }

            ChallengeReadResult readResult = challengeReader.read(
                    registration.challengeId(), registration.secret(), registration.expectedType());
            if (readResult.failureStatus() != null) {
                String failureStatus = readResult.failureStatus();
                if ("NOT_FOUND".equals(failureStatus) && registration.lastStatus() == PushChallengeStatus.PENDING) {
                    failureStatus = PushChallengeStatus.EXPIRED.name();
                }
                emitter.sendStatusEvent(
                        registration.sink(), registration.sse(), failureStatus, null, registration.type());
                unregister(registration, true);
                continue;
            }

            PushChallenge challenge = readResult.challenge();
            PushChallengeStatus currentStatus = challenge.getStatus();
            if (registration.lastStatus() != currentStatus) {
                boolean sent = emitter.sendStatusEvent(
                        registration.sink(), registration.sse(), currentStatus.name(), challenge, registration.type());
                if (!sent) {
                    unregister(registration, true);
                    continue;
                }
                registration.lastStatus(currentStatus);
            }

            if (currentStatus != PushChallengeStatus.PENDING) {
                unregister(registration, true);
            }
        }
    }

    private boolean startPoller() {
        if (pollerStarted.compareAndSet(false, true)) {
            try {
                executor.execute(this::pollLoop);
            } catch (RejectedExecutionException ex) {
                pollerStarted.set(false);
                return false;
            }
        }
        return true;
    }

    private void pollLoop() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                pollOnce();
                Thread.sleep(POLL_INTERVAL_MILLIS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                LOG.info("Push MFA SSE registry poller interrupted");
                return;
            } catch (RuntimeException ex) {
                LOG.warn("Push MFA SSE registry poll failed", ex);
            }
        }
    }

    private ArrayList<Registration> snapshotRegistrations() {
        synchronized (registrations) {
            return new ArrayList<>(registrations.values());
        }
    }

    private void unregister(Registration registration, boolean closeSink) {
        boolean removed;
        synchronized (registrations) {
            removed = registrations.remove(registration.id(), registration);
        }
        if (!removed) {
            return;
        }
        permits.release();
        if (closeSink) {
            try {
                registration.sink().close();
            } catch (Exception ignored) {
                // no-op
            }
        }
    }

    private static ChallengeReader createChallengeReader(KeycloakSessionFactory sessionFactory) {
        return (challengeId, secret, expectedType) ->
                KeycloakModelUtils.runJobInTransactionWithResult(sessionFactory, session -> {
                    PushChallengeStore challengeStore = new PushChallengeStore(session);
                    Optional<PushChallenge> challengeOpt = challengeStore.get(challengeId);
                    if (challengeOpt.isEmpty()) {
                        return ChallengeReadResult.failure("NOT_FOUND");
                    }

                    PushChallenge challenge = challengeOpt.get();
                    if (expectedType != null && challenge.getType() != expectedType) {
                        return ChallengeReadResult.failure("BAD_TYPE");
                    }
                    if (!Objects.equals(secret, challenge.getWatchSecret())) {
                        return ChallengeReadResult.failure("FORBIDDEN");
                    }
                    return ChallengeReadResult.success(challenge);
                });
    }

    private static ExecutorService createExecutor() {
        return java.util.concurrent.Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "push-mfa-sse-poller");
            thread.setDaemon(true);
            return thread;
        });
    }

    record ChallengeReadResult(PushChallenge challenge, String failureStatus) {
        static ChallengeReadResult success(PushChallenge challenge) {
            return new ChallengeReadResult(challenge, null);
        }

        static ChallengeReadResult failure(String failureStatus) {
            return new ChallengeReadResult(null, failureStatus);
        }
    }

    private record Registration(
            String id,
            String challengeId,
            String secret,
            SseEventSink sink,
            Sse sse,
            SseEventEmitter.EventType type,
            PushChallenge.Type expectedType,
            java.util.concurrent.atomic.AtomicReference<PushChallengeStatus> lastStatusRef) {
        Registration(
                String id,
                String challengeId,
                String secret,
                SseEventSink sink,
                Sse sse,
                SseEventEmitter.EventType type,
                PushChallenge.Type expectedType,
                PushChallengeStatus lastStatus) {
            this(
                    id,
                    challengeId,
                    secret,
                    sink,
                    sse,
                    type,
                    expectedType,
                    new java.util.concurrent.atomic.AtomicReference<>(lastStatus));
        }

        PushChallengeStatus lastStatus() {
            return lastStatusRef.get();
        }

        void lastStatus(PushChallengeStatus status) {
            lastStatusRef.set(status);
        }
    }
}
