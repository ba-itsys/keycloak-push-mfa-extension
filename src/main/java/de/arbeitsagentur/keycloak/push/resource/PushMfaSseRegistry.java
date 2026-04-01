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
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.utils.StringUtil;

final class PushMfaSseRegistry {

    private static final Logger LOG = Logger.getLogger(PushMfaSseRegistry.class);
    private static final long POLL_INTERVAL_MILLIS = 1000L;

    private final int maxConnections;
    private final long heartbeatIntervalMillis;
    private final long maxConnectionLifetimeMillis;
    private final Semaphore permits;
    private final Executor executor;
    private final Function<ChallengeReadRequest, ChallengeReadResult> challengeReader;
    private final SseEventEmitter emitter;
    private final AtomicBoolean pollerStarted = new AtomicBoolean();
    private final Map<String, ChallengeWatchGroup> registrations = new HashMap<>();

    PushMfaSseRegistry(
            int maxConnections,
            long heartbeatIntervalMillis,
            long maxConnectionLifetimeMillis,
            KeycloakSessionFactory sessionFactory,
            ExecutorService executor) {
        this(
                maxConnections,
                heartbeatIntervalMillis,
                maxConnectionLifetimeMillis,
                createChallengeReader(sessionFactory),
                new SseEventEmitter(),
                executor);
    }

    PushMfaSseRegistry(
            int maxConnections,
            long heartbeatIntervalMillis,
            long maxConnectionLifetimeMillis,
            Function<ChallengeReadRequest, ChallengeReadResult> challengeReader,
            SseEventEmitter emitter,
            ExecutorService executor) {
        this.maxConnections = maxConnections;
        this.heartbeatIntervalMillis = heartbeatIntervalMillis;
        this.maxConnectionLifetimeMillis = maxConnectionLifetimeMillis;
        this.permits = new Semaphore(maxConnections);
        this.challengeReader = Objects.requireNonNull(challengeReader);
        this.emitter = Objects.requireNonNull(emitter);
        this.executor = Objects.requireNonNullElseGet(executor, PushMfaSseRegistry::createExecutor);
    }

    int maxConnections() {
        return maxConnections;
    }

    ChallengeReadResult readChallenge(String challengeId, String secret, PushChallenge.Type expectedType) {
        return challengeReader.apply(new ChallengeReadRequest(challengeId, secret, expectedType));
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

        Watcher watcher = new Watcher(
                UUID.randomUUID().toString(), challengeId, sink, sse, type, lastStatus, System.currentTimeMillis());

        boolean registered = false;
        synchronized (registrations) {
            ChallengeWatchGroup group = registrations.computeIfAbsent(
                    challengeId, id -> new ChallengeWatchGroup(challengeId, secret, expectedType));
            if (group.matches(secret, expectedType)) {
                group.watchers().put(watcher.id(), watcher);
                registered = true;
            }
        }

        if (!registered) {
            permits.release();
            return false;
        }
        if (!startPoller()) {
            unregister(watcher, true);
            return false;
        }
        return true;
    }

    void pollOnce() {
        long now = System.currentTimeMillis();
        for (ChallengeWatchGroup group : snapshotGroups()) {
            ArrayList<Watcher> activeWatchers = new ArrayList<>();
            for (Watcher watcher : snapshotWatchers(group)) {
                if (ensureWatcherActive(watcher, now)) {
                    activeWatchers.add(watcher);
                }
            }
            if (activeWatchers.isEmpty()) {
                continue;
            }

            ChallengeReadResult readResult = challengeReader.apply(
                    new ChallengeReadRequest(group.challengeId(), group.secret(), group.expectedType()));
            if (readResult.failureStatus() != null) {
                for (Watcher watcher : activeWatchers) {
                    sendFailureStatus(watcher, readResult.failureStatus(), now);
                }
                continue;
            }

            PushChallenge challenge = readResult.challenge();
            PushChallengeStatus currentStatus = challenge.getStatus();
            for (Watcher watcher : activeWatchers) {
                dispatchWatcherUpdate(watcher, challenge, currentStatus, now);
            }
        }
    }

    private boolean ensureWatcherActive(Watcher watcher, long now) {
        if (watcher.sink().isClosed()) {
            unregister(watcher, false);
            return false;
        }
        if (!watcher.isSendInProgress() && now - watcher.connectedAtMillis() >= maxConnectionLifetimeMillis) {
            unregister(watcher, true);
            return false;
        }
        return true;
    }

    private void sendFailureStatus(Watcher watcher, String failureStatus, long now) {
        if (!watcher.startSend()) {
            return;
        }
        String effectiveStatus = failureStatus;
        if ("NOT_FOUND".equals(effectiveStatus) && watcher.lastStatus() == PushChallengeStatus.PENDING) {
            effectiveStatus = PushChallengeStatus.EXPIRED.name();
        }
        emitter.sendStatusEvent(watcher.sink(), watcher.sse(), effectiveStatus, null, watcher.type())
                .whenComplete((sent, ex) -> {
                    watcher.finishSend(null, now);
                    unregister(watcher, true);
                });
    }

    private void dispatchWatcherUpdate(
            Watcher watcher, PushChallenge challenge, PushChallengeStatus currentStatus, long now) {
        if (watcher.lastStatus() != currentStatus) {
            if (!watcher.startSend()) {
                return;
            }
            emitter.sendStatusEvent(
                            watcher.sink(), watcher.sse(), currentStatus.name(), challenge, watcher.type(), null)
                    .whenComplete((sent, ex) -> {
                        if (!Boolean.TRUE.equals(sent)) {
                            watcher.finishSend(null, now);
                            unregister(watcher, true);
                            return;
                        }
                        watcher.finishSend(currentStatus, now);
                        if (currentStatus != PushChallengeStatus.PENDING) {
                            unregister(watcher, true);
                        }
                    });
            return;
        }

        if (currentStatus != PushChallengeStatus.PENDING) {
            if (!watcher.isSendInProgress()) {
                unregister(watcher, true);
            }
            return;
        }

        if (now - watcher.lastActivityMillis() < heartbeatIntervalMillis || !watcher.startSend()) {
            return;
        }
        emitter.sendHeartbeat(watcher.sink(), watcher.sse()).whenComplete((sent, ex) -> {
            if (!Boolean.TRUE.equals(sent)) {
                watcher.finishSend(null, now);
                unregister(watcher, true);
                return;
            }
            watcher.finishSend(null, now);
        });
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

    private ArrayList<ChallengeWatchGroup> snapshotGroups() {
        synchronized (registrations) {
            return new ArrayList<>(registrations.values());
        }
    }

    private ArrayList<Watcher> snapshotWatchers(ChallengeWatchGroup group) {
        synchronized (registrations) {
            return new ArrayList<>(group.watchers().values());
        }
    }

    private void unregister(Watcher watcher, boolean closeSink) {
        boolean removed = false;
        synchronized (registrations) {
            ChallengeWatchGroup group = registrations.get(watcher.challengeId());
            if (group != null) {
                removed = group.watchers().remove(watcher.id(), watcher);
                if (group.watchers().isEmpty()) {
                    registrations.remove(watcher.challengeId());
                }
            }
        }
        if (!removed) {
            return;
        }
        permits.release();
        if (closeSink) {
            try {
                watcher.sink().close();
            } catch (Exception ignored) {
                // no-op
            }
        }
    }

    private static Function<ChallengeReadRequest, ChallengeReadResult> createChallengeReader(
            KeycloakSessionFactory sessionFactory) {
        return request -> KeycloakModelUtils.runJobInTransactionWithResult(sessionFactory, session -> {
            PushChallengeStore challengeStore = new PushChallengeStore(session);
            Optional<PushChallenge> challengeOpt = challengeStore.get(request.challengeId());
            if (challengeOpt.isEmpty()) {
                return ChallengeReadResult.failure("NOT_FOUND");
            }

            PushChallenge challenge = challengeOpt.get();
            if (request.expectedType() != null && challenge.getType() != request.expectedType()) {
                return ChallengeReadResult.failure("BAD_TYPE");
            }
            if (challenge.getType() == PushChallenge.Type.AUTHENTICATION
                    && !isAuthenticationSessionActive(session, challenge)) {
                challengeStore.remove(request.challengeId());
                return ChallengeReadResult.failure(PushChallengeStatus.EXPIRED.name());
            }
            if (!Objects.equals(request.secret(), challenge.getWatchSecret())) {
                return ChallengeReadResult.failure("FORBIDDEN");
            }
            return ChallengeReadResult.success(challenge);
        });
    }

    static boolean isAuthenticationSessionActive(KeycloakSession session, PushChallenge challenge) {
        String rootSessionId = challenge.getRootSessionId();
        if (StringUtil.isBlank(rootSessionId)) {
            return true;
        }

        RealmModel realm = session.realms().getRealm(challenge.getRealmId());
        if (realm == null) {
            LOG.debugf(
                    "Cleaning up stale challenge %s because realm %s is gone",
                    challenge.getId(), challenge.getRealmId());
            return false;
        }

        var rootSession = session.authenticationSessions().getRootAuthenticationSession(realm, rootSessionId);
        if (rootSession != null) {
            return true;
        }

        LOG.debugf("Cleaning up stale challenge %s because auth session %s is gone", challenge.getId(), rootSessionId);
        return false;
    }

    private static ExecutorService createExecutor() {
        return Executors.newSingleThreadExecutor(runnable -> {
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

    record ChallengeReadRequest(String challengeId, String secret, PushChallenge.Type expectedType) {}

    private static final class ChallengeWatchGroup {
        private final String challengeId;
        private final String secret;
        private final PushChallenge.Type expectedType;
        private final Map<String, Watcher> watchers = new HashMap<>();

        private ChallengeWatchGroup(String challengeId, String secret, PushChallenge.Type expectedType) {
            this.challengeId = challengeId;
            this.secret = secret;
            this.expectedType = expectedType;
        }

        private String challengeId() {
            return challengeId;
        }

        private String secret() {
            return secret;
        }

        private PushChallenge.Type expectedType() {
            return expectedType;
        }

        private Map<String, Watcher> watchers() {
            return watchers;
        }

        private boolean matches(String secret, PushChallenge.Type expectedType) {
            return Objects.equals(this.secret, secret) && this.expectedType == expectedType;
        }
    }

    private static final class Watcher {
        private final String id;
        private final String challengeId;
        private final SseEventSink sink;
        private final Sse sse;
        private final SseEventEmitter.EventType type;
        private final long connectedAtMillis;
        private PushChallengeStatus lastStatus;
        private long lastActivityMillis;
        private boolean sendInProgress;

        private Watcher(
                String id,
                String challengeId,
                SseEventSink sink,
                Sse sse,
                SseEventEmitter.EventType type,
                PushChallengeStatus lastStatus,
                long connectedAtMillis) {
            this.id = id;
            this.challengeId = challengeId;
            this.sink = sink;
            this.sse = sse;
            this.type = type;
            this.lastStatus = lastStatus;
            this.connectedAtMillis = connectedAtMillis;
            this.lastActivityMillis = connectedAtMillis;
        }

        private String id() {
            return id;
        }

        private String challengeId() {
            return challengeId;
        }

        private SseEventSink sink() {
            return sink;
        }

        private Sse sse() {
            return sse;
        }

        private SseEventEmitter.EventType type() {
            return type;
        }

        private synchronized PushChallengeStatus lastStatus() {
            return lastStatus;
        }

        private long connectedAtMillis() {
            return connectedAtMillis;
        }

        private synchronized long lastActivityMillis() {
            return lastActivityMillis;
        }

        private synchronized boolean startSend() {
            if (sendInProgress) {
                return false;
            }
            sendInProgress = true;
            return true;
        }

        private synchronized void finishSend(PushChallengeStatus newStatus, long now) {
            if (newStatus != null) {
                lastStatus = newStatus;
            }
            lastActivityMillis = now;
            sendInProgress = false;
        }

        private synchronized boolean isSendInProgress() {
            return sendInProgress;
        }
    }
}
