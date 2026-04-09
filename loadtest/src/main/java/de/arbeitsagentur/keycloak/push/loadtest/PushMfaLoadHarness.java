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

package de.arbeitsagentur.keycloak.push.loadtest;

import de.arbeitsagentur.keycloak.push.support.AdminClient;
import de.arbeitsagentur.keycloak.push.support.BrowserSession;
import de.arbeitsagentur.keycloak.push.support.DeviceClient;
import de.arbeitsagentur.keycloak.push.support.DeviceKeyType;
import de.arbeitsagentur.keycloak.push.support.DeviceState;
import de.arbeitsagentur.keycloak.push.support.HtmlPage;
import de.arbeitsagentur.keycloak.push.support.SseClient;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public final class PushMfaLoadHarness {

    private static final URI ADMIN_BASE_URI =
            URI.create(System.getProperty("load.adminBaseUri", "http://localhost:18080"));
    private static final List<URI> BROWSER_BASE_URIS =
            parseUris(System.getProperty("load.browserBaseUris", "http://localhost:18081,http://localhost:18082"));
    private static final List<URI> ENROLLMENT_DEVICE_BASE_URIS = parseUris(
            System.getProperty("load.enrollmentDeviceBaseUris", "http://localhost:18081,http://localhost:18082"));
    private static final List<URI> DEVICE_BASE_URIS =
            parseUris(System.getProperty("load.deviceBaseUris", "http://localhost:18082,http://localhost:18081"));
    private static final String REALM_NAME = System.getProperty("load.realm", "demo");
    private static final String ADMIN_REALM_NAME = System.getProperty("load.adminRealm", "master");
    private static final String ADMIN_USERNAME = System.getProperty("load.adminUsername", "admin");
    private static final String ADMIN_PASSWORD = System.getProperty("load.adminPassword", "admin");
    private static final String ADMIN_CLIENT_ID = System.getProperty("load.adminClientId", "admin-cli");
    private static final String BROWSER_CLIENT_ID = System.getProperty("load.browserClientId", "test-app");
    private static final String BROWSER_REDIRECT_URI =
            System.getProperty("load.browserRedirectUri", "http://localhost:8080/test-app/callback");
    private static final String DEVICE_CLIENT_ID = System.getProperty("load.deviceClientId", "push-device-client");
    private static final String DEVICE_CLIENT_SECRET =
            System.getProperty("load.deviceClientSecret", "device-client-secret");
    private static final int USER_COUNT = Integer.getInteger("load.userCount", 30);
    private static final int RATE_PER_SECOND = Integer.getInteger("load.ratePerSecond", 10);
    private static final int DURATION_SECONDS = Integer.getInteger("load.durationSeconds", 30);
    private static final int WORKER_THREADS = Integer.getInteger("load.workerThreads", 20);
    private static final String USER_PREFIX = System.getProperty("load.userPrefix", "load-user-");
    private static final String PASSWORD = System.getProperty("load.password", "load-test");
    private static final Duration SSE_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration SSE_STATUS_TIMEOUT = Duration.ofSeconds(15);

    private PushMfaLoadHarness() {}

    public static void main(String[] args) throws Exception {
        Instant overallStartedAt = Instant.now();
        System.out.println("Admin base URI: " + ADMIN_BASE_URI);
        System.out.println("Realm: " + REALM_NAME);
        System.out.println("Admin realm: " + ADMIN_REALM_NAME);
        System.out.println("Browser base URIs: " + BROWSER_BASE_URIS);
        System.out.println("Enrollment device base URIs: " + ENROLLMENT_DEVICE_BASE_URIS);
        System.out.println("Device base URIs: " + DEVICE_BASE_URIS);
        System.out.println("Browser client ID: " + BROWSER_CLIENT_ID);
        System.out.println("Browser redirect URI: " + BROWSER_REDIRECT_URI);
        System.out.println("Device client ID: " + DEVICE_CLIENT_ID);
        System.out.println("Users: " + USER_COUNT);
        System.out.println("Rate: " + RATE_PER_SECOND + " logins/s");
        System.out.println("Duration: " + DURATION_SECONDS + "s");
        System.out.println("Workers: " + WORKER_THREADS);

        AdminClient admin = new AdminClient(
                ADMIN_BASE_URI,
                REALM_NAME,
                ADMIN_REALM_NAME,
                ADMIN_USERNAME,
                ADMIN_PASSWORD,
                ADMIN_CLIENT_ID);
        admin.configurePushMfaUserVerification("none");
        admin.configurePushMfaAutoAddRequiredAction(true);
        admin.disablePushMfaWaitChallenge();

        BlockingQueue<UserContext> availableUsers = new LinkedBlockingQueue<>();
        for (int i = 1; i <= USER_COUNT; i++) {
            String username = USER_PREFIX + i;
            admin.ensureUser(username, PASSWORD);
            admin.resetUserState(username);

            URI browserBaseUri = pickUri(BROWSER_BASE_URIS, i - 1);
            URI enrollmentDeviceBaseUri = pickUri(ENROLLMENT_DEVICE_BASE_URIS, i - 1);
            URI deviceBaseUri = pickUri(DEVICE_BASE_URIS, i - 1);
            BrowserSession browser = new BrowserSession(browserBaseUri, REALM_NAME, BROWSER_REDIRECT_URI);
            DeviceClient device = enrollUser(username, PASSWORD, browser, enrollmentDeviceBaseUri, deviceBaseUri);
            browser.resetSession();
            availableUsers.add(new UserContext(username, PASSWORD, device, browser));
            System.out.println("Enrolled " + username + " browser=" + browserBaseUri + " enroll-device="
                    + enrollmentDeviceBaseUri + " login-device=" + deviceBaseUri);
        }

        Instant loadStartedAt = Instant.now();
        int totalAttempts = RATE_PER_SECOND * DURATION_SECONDS;
        AtomicInteger started = new AtomicInteger();
        AtomicInteger completed = new AtomicInteger();
        AtomicInteger succeeded = new AtomicInteger();
        AtomicInteger failed = new AtomicInteger();
        AtomicInteger userPoolTimeouts = new AtomicInteger();
        ConcurrentLinkedQueue<Long> latenciesMillis = new ConcurrentLinkedQueue<>();
        ConcurrentHashMap<String, AtomicInteger> failures = new ConcurrentHashMap<>();
        CountDownLatch finished = new CountDownLatch(totalAttempts);

        ThreadPoolExecutor workers = (ThreadPoolExecutor) Executors.newFixedThreadPool(WORKER_THREADS);
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

        for (int i = 0; i < totalAttempts; i++) {
            long delayMillis = Math.round(i * (1000.0d / RATE_PER_SECOND));
            scheduler.schedule(
                    () -> workers.submit(() -> {
                        started.incrementAndGet();
                        long begin = System.nanoTime();
                        UserContext user = null;
                        try {
                            user = availableUsers.poll(30, TimeUnit.SECONDS);
                            if (user == null) {
                                userPoolTimeouts.incrementAndGet();
                                failed.incrementAndGet();
                                recordFailure(failures, "user-pool-timeout");
                                return;
                            }
                            runLoginFlow(user);
                            long latencyMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - begin);
                            latenciesMillis.add(latencyMillis);
                            succeeded.incrementAndGet();
                        } catch (Throwable t) {
                            failed.incrementAndGet();
                            recordFailure(failures, summarize(t));
                        } finally {
                            if (user != null) {
                                availableUsers.offer(user);
                            }
                            completed.incrementAndGet();
                            finished.countDown();
                        }
                    }),
                    delayMillis,
                    TimeUnit.MILLISECONDS);
        }

        scheduler.shutdown();
        scheduler.awaitTermination(DURATION_SECONDS + 30L, TimeUnit.SECONDS);

        boolean allFinished = finished.await(DURATION_SECONDS + 120L, TimeUnit.SECONDS);
        workers.shutdown();
        workers.awaitTermination(30, TimeUnit.SECONDS);

        long loadElapsedMillis = Duration.between(loadStartedAt, Instant.now()).toMillis();
        long overallElapsedMillis = Duration.between(overallStartedAt, Instant.now()).toMillis();
        List<Long> sortedLatencies = new ArrayList<>(latenciesMillis);
        sortedLatencies.sort(Comparator.naturalOrder());

        System.out.println();
        System.out.println("Summary");
        System.out.println("Started: " + started.get());
        System.out.println("Completed: " + completed.get());
        System.out.println("Succeeded: " + succeeded.get());
        System.out.println("Failed: " + failed.get());
        System.out.println("User pool timeouts: " + userPoolTimeouts.get());
        System.out.println("All finished: " + allFinished);
        System.out.println("Load elapsed ms: " + loadElapsedMillis);
        System.out.println("Overall elapsed ms: " + overallElapsedMillis);
        System.out.println("Observed throughput/s: " + formatRate(completed.get(), loadElapsedMillis));
        System.out.println("Latency p50 ms: " + percentile(sortedLatencies, 50));
        System.out.println("Latency p95 ms: " + percentile(sortedLatencies, 95));
        System.out.println("Latency p99 ms: " + percentile(sortedLatencies, 99));
        System.out.println(
                "Latency max ms: " + (sortedLatencies.isEmpty() ? 0 : sortedLatencies.get(sortedLatencies.size() - 1)));
        System.out.println();
        System.out.println("Top failures");
        if (failures.isEmpty()) {
            System.out.println("none");
        } else {
            new TreeMap<>(failures).forEach((key, value) -> System.out.println(value.get() + " x " + key));
        }

        if (!allFinished || failed.get() > 0) {
            System.exit(1);
        }
    }

    private static DeviceClient enrollUser(
            String username,
            String password,
            BrowserSession session,
            URI enrollmentDeviceBaseUri,
            URI deviceBaseUri)
            throws Exception {
        DeviceState state = DeviceState.create(DeviceKeyType.RSA);
        DeviceClient enrollmentDevice =
                new DeviceClient(enrollmentDeviceBaseUri, REALM_NAME, DEVICE_CLIENT_ID, DEVICE_CLIENT_SECRET, state);
        HtmlPage loginPage = session.startAuthorization(BROWSER_CLIENT_ID);
        HtmlPage enrollPage = session.submitLogin(loginPage, username, password);
        String token = session.extractEnrollmentToken(enrollPage);
        enrollmentDevice.completeEnrollment(token);
        session.submitEnrollmentCheck(enrollPage);
        return new DeviceClient(deviceBaseUri, REALM_NAME, DEVICE_CLIENT_ID, DEVICE_CLIENT_SECRET, state);
    }

    private static void runLoginFlow(UserContext user) throws Exception {
        BrowserSession session = user.browser();
        session.resetSession();
        HtmlPage loginPage = session.startAuthorization(BROWSER_CLIENT_ID);
        HtmlPage waitingPage = session.submitLogin(loginPage, user.username(), user.password());
        BrowserSession.DeviceChallenge challenge = session.extractDeviceChallenge(waitingPage);
        URI eventsUri = session.extractLoginEventsUri(waitingPage);
        try (SseClient sseClient = new SseClient(eventsUri)) {
            int statusCode = sseClient.awaitStatusCode(SSE_CONNECT_TIMEOUT);
            if (statusCode != 200) {
                throw new IllegalStateException("Unexpected SSE status code: " + statusCode);
            }
            user.device().respondToChallenge(challenge.confirmToken(), challenge.challengeId());
            long deadlineNanos = System.nanoTime() + SSE_STATUS_TIMEOUT.toNanos();
            while (true) {
                long remainingNanos = deadlineNanos - System.nanoTime();
                if (remainingNanos <= 0L) {
                    throw new IllegalStateException("Timed out waiting for APPROVED SSE status");
                }
                String status = sseClient.awaitStatus(Duration.ofNanos(remainingNanos));
                if (status == null) {
                    throw new IllegalStateException("Timed out waiting for APPROVED SSE status");
                }
                if ("APPROVED".equals(status)) {
                    break;
                }
                if (!"PENDING".equals(status)) {
                    throw new IllegalStateException("Unexpected SSE status: " + status);
                }
            }
        }
        session.completePushChallenge(challenge.formAction());
    }

    private static void recordFailure(Map<String, AtomicInteger> failures, String key) {
        failures.computeIfAbsent(key, ignored -> new AtomicInteger()).incrementAndGet();
    }

    private static String summarize(Throwable t) {
        Throwable current = t;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        String type = current.getClass().getSimpleName();
        String message = Objects.toString(current.getMessage(), "").replaceAll("\\s+", " ").trim();
        if (message.length() > 180) {
            message = message.substring(0, 180);
        }
        return message.isBlank() ? type : type + ": " + message;
    }

    private static String formatRate(int completed, long elapsedMillis) {
        if (elapsedMillis <= 0L) {
            return "0.00";
        }
        return String.format("%.2f", completed / (elapsedMillis / 1000.0d));
    }

    private static long percentile(List<Long> values, int percentile) {
        if (values.isEmpty()) {
            return 0L;
        }
        int index = (int) Math.ceil((percentile / 100.0d) * values.size()) - 1;
        index = Math.max(0, Math.min(index, values.size() - 1));
        return values.get(index);
    }

    private static List<URI> parseUris(String csv) {
        return Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .map(URI::create)
                .toList();
    }

    private static URI pickUri(List<URI> uris, int index) {
        if (uris.isEmpty()) {
            throw new IllegalStateException("At least one URI is required");
        }
        return uris.get(index % uris.size());
    }

    private record UserContext(String username, String password, DeviceClient device, BrowserSession browser) {}
}
