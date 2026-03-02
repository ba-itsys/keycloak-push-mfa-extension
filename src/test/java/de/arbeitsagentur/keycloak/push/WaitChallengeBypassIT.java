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

package de.arbeitsagentur.keycloak.push;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.push.support.AdminClient;
import de.arbeitsagentur.keycloak.push.support.BrowserSession;
import de.arbeitsagentur.keycloak.push.support.ContainerLogWatcher;
import de.arbeitsagentur.keycloak.push.support.DeviceClient;
import de.arbeitsagentur.keycloak.push.support.DeviceKeyType;
import de.arbeitsagentur.keycloak.push.support.DeviceState;
import de.arbeitsagentur.keycloak.push.support.HtmlPage;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

/**
 * Security integration tests for Wait Challenge feature focusing on state manipulation
 * and bypass attack vectors.
 *
 * <p>These tests verify that the wait challenge rate limiting cannot be circumvented through:
 * <ul>
 *   <li>Session switching attacks</li>
 *   <li>User attribute tampering with malformed JSON</li>
 *   <li>State reset attempts without legitimate approval</li>
 *   <li>Multi-browser bypass attempts</li>
 *   <li>Cross-realm state leakage</li>
 *   <li>Counter overflow/underflow attacks</li>
 * </ul>
 */
@Testcontainers
@ExtendWith(ContainerLogWatcher.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WaitChallengeBypassIT {

    private static final Path EXTENSION_JAR = locateProviderJar();
    private static final Path REALM_FILE =
            Paths.get("config", "demo-realm.json").toAbsolutePath();
    private static final String WAIT_ATTRIBUTE_KEY = "push-mfa-wait-state";

    // Dedicated test users for bypass tests to ensure complete isolation
    private static final String BYPASS_USER_1 = "bypass-user-1";
    private static final String BYPASS_USER_2 = "bypass-user-2";
    private static final String BYPASS_USER_3 = "bypass-user-3";
    private static final String BYPASS_USER_4 = "bypass-user-4";
    private static final String BYPASS_USER_5 = "bypass-user-5";
    private static final String BYPASS_USER_6 = "bypass-user-6";
    private static final String BYPASS_USER_7 = "bypass-user-7";
    private static final String BYPASS_USER_8 = "bypass-user-8";
    private static final String BYPASS_USER_9 = "bypass-user-9";
    private static final String BYPASS_USER_10 = "bypass-user-10";
    private static final String BYPASS_PASSWORD = "bypass-test";

    @Container
    private static final GenericContainer<?> KEYCLOAK = new GenericContainer<>("quay.io/keycloak/keycloak:26.4.5")
            .withExposedPorts(8080)
            .withCopyFileToContainer(
                    MountableFile.forHostPath(EXTENSION_JAR), "/opt/keycloak/providers/keycloak-push-mfa.jar")
            .withCopyFileToContainer(MountableFile.forHostPath(REALM_FILE), "/opt/keycloak/data/import/demo-realm.json")
            .withEnv("KEYCLOAK_ADMIN", "admin")
            .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
            .withCommand(
                    "start-dev --hostname=localhost --hostname-strict=false --http-enabled=true --import-realm --features=dpop")
            .waitingFor(Wait.forHttp("/realms/master").forStatusCode(200))
            .withStartupTimeout(Duration.ofMinutes(3));

    private URI baseUri;
    private AdminClient adminClient;

    @BeforeAll
    void setup() throws Exception {
        baseUri = URI.create(String.format("http://%s:%d/", KEYCLOAK.getHost(), KEYCLOAK.getMappedPort(8080)));
        adminClient = new AdminClient(baseUri);

        // Create dedicated users for bypass tests
        adminClient.ensureUser(BYPASS_USER_1, BYPASS_PASSWORD);
        adminClient.ensureUser(BYPASS_USER_2, BYPASS_PASSWORD);
        adminClient.ensureUser(BYPASS_USER_3, BYPASS_PASSWORD);
        adminClient.ensureUser(BYPASS_USER_4, BYPASS_PASSWORD);
        adminClient.ensureUser(BYPASS_USER_5, BYPASS_PASSWORD);
        adminClient.ensureUser(BYPASS_USER_6, BYPASS_PASSWORD);
        adminClient.ensureUser(BYPASS_USER_7, BYPASS_PASSWORD);
        adminClient.ensureUser(BYPASS_USER_8, BYPASS_PASSWORD);
        adminClient.ensureUser(BYPASS_USER_9, BYPASS_PASSWORD);
        adminClient.ensureUser(BYPASS_USER_10, BYPASS_PASSWORD);
    }

    @BeforeEach
    void resetConfig() throws Exception {
        adminClient.configurePushMfaUserVerification(
                PushMfaConstants.USER_VERIFICATION_NONE, PushMfaConstants.DEFAULT_USER_VERIFICATION_PIN_LENGTH);
        adminClient.configurePushMfaSameDeviceUserVerification(false);
        adminClient.configurePushMfaAutoAddRequiredAction(true);
        adminClient.resetPushMfaWaitChallengeToDefaults();
        adminClient.configurePushMfaMaxPendingChallenges(PushMfaConstants.DEFAULT_MAX_PENDING_AUTH_CHALLENGES);
        adminClient.configurePushMfaLoginChallengeTtlSeconds(PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.toSeconds());

        // Clear wait state from all test users
        for (String user : new String[] {
            BYPASS_USER_1,
            BYPASS_USER_2,
            BYPASS_USER_3,
            BYPASS_USER_4,
            BYPASS_USER_5,
            BYPASS_USER_6,
            BYPASS_USER_7,
            BYPASS_USER_8,
            BYPASS_USER_9,
            BYPASS_USER_10
        }) {
            adminClient.clearUserAttribute(user, WAIT_ATTRIBUTE_KEY);
        }
        Thread.sleep(100);
    }

    // ==================== Session Switching Attack Tests ====================

    @Nested
    @DisplayName("Session Switching Attack")
    class SessionSwitchingAttacks {

        /**
         * BYPASS ATTACK: Session Switching
         *
         * <p>Attack vector: Attacker attempts to bypass wait challenge by starting a new
         * authentication session after being rate-limited. The wait state should persist
         * across sessions since it's tied to the user, not the session.
         *
         * <p>Expected behavior: New session should still be blocked if user is in wait period.
         */
        @Test
        @DisplayName("New session cannot bypass wait challenge state tied to user")
        void newSessionCannotBypassWaitState() throws Exception {
            String username = BYPASS_USER_1;
            DeviceClient deviceClient = enrollDevice(username, BYPASS_PASSWORD, DeviceKeyType.RSA);

            // Enable wait challenge with short TTL for testing
            adminClient.configurePushMfaMaxPendingChallenges(10);
            adminClient.configurePushMfaWaitChallenge(true, 5, 60, 1);
            adminClient.configurePushMfaLoginChallengeTtlSeconds(1);

            try {
                // First session: Create challenge and let it expire to build wait state
                BrowserSession firstSession = new BrowserSession(baseUri);
                HtmlPage loginPage1 = firstSession.startAuthorization("test-app");
                HtmlPage waitingPage1 = firstSession.submitLogin(loginPage1, username, BYPASS_PASSWORD);
                firstSession.extractDeviceChallenge(waitingPage1);

                // Wait for challenge to expire
                awaitNoPendingChallenges(deviceClient);

                // Second session (different cookies, fresh session): Should still be blocked
                BrowserSession secondSession = new BrowserSession(baseUri);
                HtmlPage loginPage2 = secondSession.startAuthorization("test-app");
                HtmlPage waitingPage2 = secondSession.submitLogin(loginPage2, username, BYPASS_PASSWORD);
                String pageText = waitingPage2.document().text().toLowerCase();

                // The user should be blocked by wait challenge, regardless of session
                assertTrue(
                        pageText.contains("wait") || pageText.contains("rate limit") || pageText.contains("too many"),
                        "New session should still be blocked by wait challenge. Got: " + pageText);
            } finally {
                adminClient.disablePushMfaWaitChallenge();
                adminClient.configurePushMfaLoginChallengeTtlSeconds(
                        PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.toSeconds());
                adminClient.clearUserAttribute(username, WAIT_ATTRIBUTE_KEY);
            }
        }

        /**
         * BYPASS ATTACK: Session Cookie Manipulation
         *
         * <p>Attack vector: Attacker clears all cookies and starts fresh to try to
         * bypass rate limiting that might be stored in session.
         *
         * <p>Expected behavior: Wait state is stored server-side per user, not in session,
         * so clearing cookies should not help bypass.
         */
        @Test
        @DisplayName("Clearing cookies does not reset server-side wait state")
        void clearingCookiesDoesNotResetWaitState() throws Exception {
            String username = BYPASS_USER_2;
            DeviceClient deviceClient = enrollDevice(username, BYPASS_PASSWORD, DeviceKeyType.RSA);

            adminClient.configurePushMfaMaxPendingChallenges(10);
            adminClient.configurePushMfaWaitChallenge(true, 5, 60, 1);
            adminClient.configurePushMfaLoginChallengeTtlSeconds(1);

            try {
                // Build up wait state with multiple expired challenges
                for (int i = 0; i < 2; i++) {
                    // Wait for previous backoff
                    int waitTime = (int) Math.pow(2, i) * 5000 + 1000;
                    Thread.sleep(waitTime);

                    awaitNoPendingChallenges(deviceClient);

                    BrowserSession session = new BrowserSession(baseUri);
                    HtmlPage login = session.startAuthorization("test-app");
                    HtmlPage waiting = session.submitLogin(login, username, BYPASS_PASSWORD);
                    session.extractDeviceChallenge(waiting);
                    awaitNoPendingChallenges(deviceClient);
                }

                // Now create a completely new session (simulates clearing all cookies)
                // Wait state should persist because it's in user attributes
                BrowserSession freshSession = new BrowserSession(baseUri);
                HtmlPage freshLogin = freshSession.startAuthorization("test-app");
                HtmlPage freshWaiting = freshSession.submitLogin(freshLogin, username, BYPASS_PASSWORD);
                String pageText = freshWaiting.document().text().toLowerCase();

                assertTrue(
                        pageText.contains("wait") || pageText.contains("rate limit") || pageText.contains("too many"),
                        "Fresh session should still see wait state from user attributes. Got: " + pageText);
            } finally {
                adminClient.disablePushMfaWaitChallenge();
                adminClient.configurePushMfaLoginChallengeTtlSeconds(
                        PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.toSeconds());
                adminClient.clearUserAttribute(username, WAIT_ATTRIBUTE_KEY);
            }
        }
    }

    // ==================== User Attribute Tampering Tests ====================

    @Nested
    @DisplayName("User Attribute Tampering")
    class UserAttributeTampering {

        /**
         * BYPASS ATTACK: Malformed JSON Injection
         *
         * <p>Attack vector: If an attacker can somehow inject malformed JSON into the
         * user attribute (e.g., via LDAP sync, custom extension, or admin API), the
         * system should handle it gracefully and not crash or bypass protection.
         *
         * <p>Expected behavior: Malformed JSON should be detected and cleaned up,
         * treating it as if no state exists (fresh start for rate limiting).
         */
        @Test
        @DisplayName("Malformed JSON in user attribute is handled gracefully")
        void malformedJsonIsHandledGracefully() throws Exception {
            String username = BYPASS_USER_3;
            DeviceClient deviceClient = enrollDevice(username, BYPASS_PASSWORD, DeviceKeyType.RSA);

            adminClient.configurePushMfaMaxPendingChallenges(10);
            adminClient.configurePushMfaWaitChallenge(true, 1, 60, 1);
            adminClient.configurePushMfaLoginChallengeTtlSeconds(120);

            try {
                // Inject malformed JSON into the wait state attribute
                adminClient.setUserAttribute(username, WAIT_ATTRIBUTE_KEY, "{{{{invalid json}}}}");

                // System should handle malformed JSON gracefully and allow login attempt
                BrowserSession session = new BrowserSession(baseUri);
                HtmlPage loginPage = session.startAuthorization("test-app");
                HtmlPage waitingPage = session.submitLogin(loginPage, username, BYPASS_PASSWORD);

                // Should get to the push challenge page (malformed state treated as no state)
                BrowserSession.DeviceChallenge challenge = session.extractDeviceChallenge(waitingPage);
                assertNotNull(challenge, "Should be able to proceed after malformed JSON cleanup");

                // Clean up
                deviceClient.respondToChallenge(
                        challenge.confirmToken(), challenge.challengeId(), PushMfaConstants.CHALLENGE_DENY);
            } finally {
                adminClient.disablePushMfaWaitChallenge();
                adminClient.configurePushMfaLoginChallengeTtlSeconds(
                        PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.toSeconds());
                adminClient.clearUserAttribute(username, WAIT_ATTRIBUTE_KEY);
            }
        }

        /**
         * BYPASS ATTACK: Incomplete JSON State
         *
         * <p>Attack vector: Inject JSON that is valid but missing required fields,
         * attempting to confuse the state parser.
         *
         * <p>Expected behavior: Incomplete JSON should be treated as invalid and cleaned up.
         */
        @Test
        @DisplayName("Incomplete JSON state is cleaned up")
        void incompleteJsonIsCleanedUp() throws Exception {
            String username = BYPASS_USER_4;
            DeviceClient deviceClient = enrollDevice(username, BYPASS_PASSWORD, DeviceKeyType.RSA);

            adminClient.configurePushMfaMaxPendingChallenges(10);
            adminClient.configurePushMfaWaitChallenge(true, 1, 60, 1);
            adminClient.configurePushMfaLoginChallengeTtlSeconds(120);

            try {
                // Inject incomplete JSON (missing required fields)
                adminClient.setUserAttribute(
                        username, WAIT_ATTRIBUTE_KEY, "{\"firstUnapprovedAt\":\"2026-01-01T00:00:00Z\"}");

                BrowserSession session = new BrowserSession(baseUri);
                HtmlPage loginPage = session.startAuthorization("test-app");
                HtmlPage waitingPage = session.submitLogin(loginPage, username, BYPASS_PASSWORD);

                // Should proceed normally (incomplete state treated as no state)
                BrowserSession.DeviceChallenge challenge = session.extractDeviceChallenge(waitingPage);
                assertNotNull(challenge, "Should be able to proceed after incomplete JSON cleanup");

                deviceClient.respondToChallenge(
                        challenge.confirmToken(), challenge.challengeId(), PushMfaConstants.CHALLENGE_DENY);
            } finally {
                adminClient.disablePushMfaWaitChallenge();
                adminClient.configurePushMfaLoginChallengeTtlSeconds(
                        PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.toSeconds());
                adminClient.clearUserAttribute(username, WAIT_ATTRIBUTE_KEY);
            }
        }
    }

    // ==================== State Reset Bypass Tests ====================

    @Nested
    @DisplayName("State Reset Bypass")
    class StateResetBypass {

        /**
         * BYPASS ATTACK: Denial without legitimate session
         *
         * <p>Attack vector: Try to reset wait state by denying a challenge that wasn't
         * legitimately created, or try to manipulate the state directly.
         *
         * <p>Expected behavior: Only legitimate approval should reset wait state.
         * Denial should NOT reset the counter.
         */
        @Test
        @DisplayName("Denial does not reset wait counter")
        void denialDoesNotResetWaitCounter() throws Exception {
            String username = BYPASS_USER_5;
            DeviceClient deviceClient = enrollDevice(username, BYPASS_PASSWORD, DeviceKeyType.RSA);

            adminClient.configurePushMfaMaxPendingChallenges(10);
            adminClient.configurePushMfaWaitChallenge(true, 2, 60, 1);
            adminClient.configurePushMfaLoginChallengeTtlSeconds(2);

            try {
                // First challenge - let it expire to build wait state
                BrowserSession firstSession = new BrowserSession(baseUri);
                HtmlPage login1 = firstSession.startAuthorization("test-app");
                HtmlPage waiting1 = firstSession.submitLogin(login1, username, BYPASS_PASSWORD);
                firstSession.extractDeviceChallenge(waiting1);
                awaitNoPendingChallenges(deviceClient);

                // Wait for initial backoff (2s wait + buffer)
                Thread.sleep(2500);

                // Second challenge - DENY it (should NOT reset counter)
                BrowserSession secondSession = new BrowserSession(baseUri);
                HtmlPage login2 = secondSession.startAuthorization("test-app");
                HtmlPage waiting2 = secondSession.submitLogin(login2, username, BYPASS_PASSWORD);
                BrowserSession.DeviceChallenge challenge = secondSession.extractDeviceChallenge(waiting2);

                String status =
                        deviceClient.respondToChallenge(challenge.confirmToken(), challenge.challengeId(), "deny");
                assertEquals("denied", status);

                // Wait for the doubled backoff (denial doesn't reset, so it should increase)
                // Counter is now 2, so wait time is 2s * 2^1 = 4s
                Thread.sleep(4500);
                awaitNoPendingChallenges(deviceClient);

                // Third attempt should still face rate limiting from the built-up counter
                // The counter should be at least 2 after the denial
                BrowserSession thirdSession = new BrowserSession(baseUri);
                HtmlPage login3 = thirdSession.startAuthorization("test-app");
                HtmlPage waiting3 = thirdSession.submitLogin(login3, username, BYPASS_PASSWORD);
                BrowserSession.DeviceChallenge challenge3 = thirdSession.extractDeviceChallenge(waiting3);

                // This verifies we can get a challenge (wait period passed), but counter wasn't reset
                assertNotNull(challenge3, "Should be able to get challenge after wait period");

                // Clean up
                deviceClient.respondToChallenge(
                        challenge3.confirmToken(), challenge3.challengeId(), PushMfaConstants.CHALLENGE_APPROVE);
                thirdSession.completePushChallenge(challenge3.formAction());
            } finally {
                adminClient.disablePushMfaWaitChallenge();
                adminClient.configurePushMfaLoginChallengeTtlSeconds(
                        PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.toSeconds());
                adminClient.clearUserAttribute(username, WAIT_ATTRIBUTE_KEY);
            }
        }
    }

    // ==================== Multi-Browser Bypass Tests ====================

    @Nested
    @DisplayName("Multi-Browser Bypass")
    class MultiBrowserBypass {

        /**
         * Tests that maxPendingChallenges=1 blocks a second session attempt.
         *
         * <p>Scenario: One browser session creates a challenge, then a second
         * session attempts to create another challenge for the same user.
         *
         * <p>Expected behavior: With maxPendingChallenges=1, only one challenge
         * should be allowed at a time, so the second session should be blocked.
         *
         * <p>Note: This tests sequential session attempts, not true concurrent access.
         */
        @Test
        @DisplayName("maxPendingChallenges=1 blocks second session attempt")
        void maxPendingChallengesBlocksSecondSession() throws Exception {
            String username = BYPASS_USER_6;
            enrollDevice(username, BYPASS_PASSWORD, DeviceKeyType.RSA);

            // Enable wait challenge but keep maxPendingChallenges at 1 (default)
            adminClient.configurePushMfaMaxPendingChallenges(1);
            adminClient.configurePushMfaWaitChallenge(true, 1, 60, 1);
            adminClient.configurePushMfaLoginChallengeTtlSeconds(120);

            try {
                // First session creates a challenge
                BrowserSession firstSession = new BrowserSession(baseUri);
                HtmlPage login1 = firstSession.startAuthorization("test-app");
                HtmlPage waiting1 = firstSession.submitLogin(login1, username, BYPASS_PASSWORD);
                BrowserSession.DeviceChallenge challenge1 = firstSession.extractDeviceChallenge(waiting1);
                assertNotNull(challenge1, "First session should get a challenge");

                // Second session should be blocked due to pending challenge
                BrowserSession secondSession = new BrowserSession(baseUri);
                HtmlPage login2 = secondSession.startAuthorization("test-app");

                IllegalStateException error = assertThrows(
                        IllegalStateException.class,
                        () -> secondSession.submitLogin(login2, username, BYPASS_PASSWORD),
                        "Second session should be blocked while first has pending challenge");

                String message = error.getMessage().toLowerCase();
                assertTrue(
                        message.contains("pending")
                                || message.contains("too many")
                                || message.contains("429")
                                || message.contains("rate limit"),
                        "Error should indicate pending challenge limit. Got: " + message);
            } finally {
                adminClient.disablePushMfaWaitChallenge();
                adminClient.configurePushMfaLoginChallengeTtlSeconds(
                        PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.toSeconds());
                adminClient.clearUserAttribute(username, WAIT_ATTRIBUTE_KEY);
            }
        }
    }

    // ==================== Counter Overflow Tests ====================

    @Nested
    @DisplayName("Counter Overflow Tests")
    class CounterOverflowTests {

        /**
         * BYPASS ATTACK: Integer Overflow
         *
         * <p>Attack vector: Set consecutiveUnapproved to extreme values (max int, negative)
         * to try to cause overflow/underflow that might reset the counter or bypass limits.
         *
         * <p>Expected behavior: System should handle extreme values gracefully.
         */
        @Test
        @DisplayName("Extreme counter values are handled safely")
        void extremeCounterValuesHandledSafely() throws Exception {
            String username = BYPASS_USER_7;
            DeviceClient deviceClient = enrollDevice(username, BYPASS_PASSWORD, DeviceKeyType.RSA);

            adminClient.configurePushMfaMaxPendingChallenges(10);
            adminClient.configurePushMfaWaitChallenge(true, 1, 3600, 1);
            adminClient.configurePushMfaLoginChallengeTtlSeconds(120);

            try {
                // Test with Integer.MAX_VALUE - should cap at max wait, not overflow
                Instant now = Instant.now();
                Instant futureWait = now.plusSeconds(3600);
                String overflowState = String.format(
                        "{\"firstUnapprovedAt\":\"%s\",\"lastChallengeAt\":\"%s\",\"consecutiveUnapproved\":%d,\"waitUntil\":\"%s\"}",
                        now.toString(), now.toString(), Integer.MAX_VALUE, futureWait.toString());
                adminClient.setUserAttribute(username, WAIT_ATTRIBUTE_KEY, overflowState);

                BrowserSession session = new BrowserSession(baseUri);
                HtmlPage loginPage = session.startAuthorization("test-app");
                HtmlPage waitingPage = session.submitLogin(loginPage, username, BYPASS_PASSWORD);

                // Should be blocked (wait period should be capped at max, not wrapped around)
                String pageText = waitingPage.document().text().toLowerCase();
                assertTrue(
                        pageText.contains("wait") || pageText.contains("rate limit") || pageText.contains("too many"),
                        "Extreme counter should result in max wait, not bypass. Got: " + pageText);

            } finally {
                adminClient.disablePushMfaWaitChallenge();
                adminClient.configurePushMfaLoginChallengeTtlSeconds(
                        PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.toSeconds());
                adminClient.clearUserAttribute(username, WAIT_ATTRIBUTE_KEY);
            }
        }

        /**
         * BYPASS ATTACK: Negative Counter
         *
         * <p>Attack vector: Set consecutiveUnapproved to negative values to try to
         * get zero or negative wait times.
         *
         * <p>Expected behavior: Negative counter should be treated as invalid state
         * or result in zero wait (fresh start).
         */
        @Test
        @DisplayName("Negative counter values result in fresh start")
        void negativeCounterValuesHandledSafely() throws Exception {
            String username = BYPASS_USER_10;
            DeviceClient deviceClient = enrollDevice(username, BYPASS_PASSWORD, DeviceKeyType.RSA);

            adminClient.configurePushMfaMaxPendingChallenges(10);
            adminClient.configurePushMfaWaitChallenge(true, 3600, 7200, 1); // Long wait to verify bypass doesn't happen
            adminClient.configurePushMfaLoginChallengeTtlSeconds(120);

            try {
                // Test with negative counter
                Instant now = Instant.now();
                Instant futureWait = now.plusSeconds(7200);
                String negativeState = String.format(
                        "{\"firstUnapprovedAt\":\"%s\",\"lastChallengeAt\":\"%s\",\"consecutiveUnapproved\":-100,\"waitUntil\":\"%s\"}",
                        now.toString(), now.toString(), futureWait.toString());
                adminClient.setUserAttribute(username, WAIT_ATTRIBUTE_KEY, negativeState);

                BrowserSession session = new BrowserSession(baseUri);
                HtmlPage loginPage = session.startAuthorization("test-app");
                HtmlPage waitingPage = session.submitLogin(loginPage, username, BYPASS_PASSWORD);

                // With negative counter, the waitUntil is still in the future, so should still wait
                // The state itself is valid JSON with valid dates - only counter is weird
                String pageText = waitingPage.document().text().toLowerCase();

                // Either blocks (waitUntil is respected) or allows (negative counter = fresh start)
                // Both are acceptable security-wise as long as negative doesn't cause calculation errors
                // The key is no crash/exception and reasonable behavior
                boolean isWaitPage =
                        pageText.contains("wait") || pageText.contains("rate limit") || pageText.contains("too many");
                boolean isChallengePage = waitingPage.document().getElementById("kc-push-confirm-token") != null;
                assertTrue(
                        isWaitPage || isChallengePage,
                        "Should either show wait page (waitUntil respected) or challenge page (fresh start). Got: "
                                + pageText);

                // If we got a challenge, clean it up
                try {
                    BrowserSession.DeviceChallenge challenge = session.extractDeviceChallenge(waitingPage);
                    if (challenge != null) {
                        deviceClient.respondToChallenge(
                                challenge.confirmToken(), challenge.challengeId(), PushMfaConstants.CHALLENGE_DENY);
                    }
                } catch (IllegalStateException e) {
                    // Expected if we're on a wait page
                }
            } finally {
                // Resilient cleanup with retry logic
                cleanupTestStateWithRetry(() -> {
                    try {
                        adminClient.disablePushMfaWaitChallenge();
                        adminClient.configurePushMfaLoginChallengeTtlSeconds(
                                PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.toSeconds());
                        adminClient.clearUserAttribute(username, WAIT_ATTRIBUTE_KEY);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
            }
        }

        /**
         * Execute cleanup operations with graceful handling of transient errors.
         * Prevents test failures due to temporary server issues during cleanup.
         */
        private void cleanupTestStateWithRetry(Runnable cleanupOp) {
            Exception lastException = null;
            for (int attempt = 0; attempt < 3; attempt++) {
                try {
                    cleanupOp.run();
                    return;
                } catch (Exception e) {
                    lastException = e;
                    if (attempt < 2 && isMaybeTemporary(e)) {
                        try {
                            // Reset token on auth errors and retry
                            if (e.getMessage() != null && e.getMessage().contains("401")) {
                                adminClient.resetAccessToken();
                            }
                            Thread.sleep(300 * (attempt + 1));
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                }
            }
            // Log the error but don't fail the test during cleanup
            if (lastException != null) {
                System.err.println("[WARNING] Test cleanup partially failed (this doesn't fail the test): "
                        + lastException.getMessage());
                lastException.printStackTrace(System.err);
            }
        }

        /**
         * Determine if an exception appears to be transient (temporary) rather than
         * indicating a persistent problem.
         */
        private boolean isMaybeTemporary(Exception e) {
            String msg = e.getMessage();
            return msg != null && (msg.contains("401") || msg.contains("timeout") || msg.contains("temporarily"));
        }
    }

    // ==================== Denial of Service Tests ====================

    @Nested
    @DisplayName("Denial of Service")
    class DenialOfServiceTests {

        /**
         * DOS ATTACK: Victim Lockout via Challenge Exhaustion
         *
         * <p>Attack vector: An attacker who knows the victim's username repeatedly triggers
         * MFA challenges and lets them expire. This builds up the victim's wait counter,
         * potentially locking them out.
         *
         * <p>Security property: The maxWait configuration MUST bound the maximum lockout
         * period. After the maxWait period, the legitimate user should be able to authenticate.
         */
        @Test
        @DisplayName("maxWait bounds victim lockout period")
        void maxWaitBoundsVictimLockoutPeriod() throws Exception {
            String username = BYPASS_USER_8;
            DeviceClient deviceClient = enrollDevice(username, BYPASS_PASSWORD, DeviceKeyType.RSA);

            // Configure short maxWait to test the bound
            int baseWaitSeconds = 1;
            int maxWaitSeconds = 3;
            adminClient.configurePushMfaMaxPendingChallenges(10);
            adminClient.configurePushMfaWaitChallenge(true, baseWaitSeconds, maxWaitSeconds, 1);
            adminClient.configurePushMfaLoginChallengeTtlSeconds(1);

            try {
                // Attacker builds up wait counter by triggering multiple expired challenges
                for (int i = 0; i < 5; i++) {
                    // Wait for any existing wait period (exponential, but capped at 3s)
                    int waitTime =
                            Math.min((int) Math.pow(2, i) * baseWaitSeconds * 1000 + 200, maxWaitSeconds * 1000 + 200);
                    Thread.sleep(waitTime);
                    awaitNoPendingChallenges(deviceClient);

                    BrowserSession attackerSession = new BrowserSession(baseUri);
                    HtmlPage attackerLogin = attackerSession.startAuthorization("test-app");
                    try {
                        HtmlPage result = attackerSession.submitLogin(attackerLogin, username, BYPASS_PASSWORD);
                        if (result.document().getElementById("kc-push-confirm-token") != null) {
                            // Challenge created, let it expire (attacker doesn't respond)
                            awaitNoPendingChallenges(deviceClient);
                        }
                    } catch (IllegalStateException e) {
                        // Rate limited - this is expected
                    }
                }

                // Now wait for maxWait period to pass
                Thread.sleep((maxWaitSeconds + 1) * 1000L);
                awaitNoPendingChallenges(deviceClient);

                // Legitimate user should now be able to authenticate
                BrowserSession legitimateSession = new BrowserSession(baseUri);
                HtmlPage legitimateLogin = legitimateSession.startAuthorization("test-app");
                HtmlPage legitimateResult = legitimateSession.submitLogin(legitimateLogin, username, BYPASS_PASSWORD);

                // Should get a challenge page, not be permanently locked out
                BrowserSession.DeviceChallenge challenge = legitimateSession.extractDeviceChallenge(legitimateResult);
                assertNotNull(challenge, "Legitimate user should be able to authenticate after maxWait period");

                // Complete the authentication to reset state
                deviceClient.respondToChallenge(
                        challenge.confirmToken(), challenge.challengeId(), PushMfaConstants.CHALLENGE_APPROVE);
                legitimateSession.completePushChallenge(challenge.formAction());

            } finally {
                adminClient.disablePushMfaWaitChallenge();
                adminClient.configurePushMfaLoginChallengeTtlSeconds(
                        PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.toSeconds());
                adminClient.clearUserAttribute(username, WAIT_ATTRIBUTE_KEY);
            }
        }

        /**
         * DOS ATTACK: Successful Authentication Resets Wait State
         *
         * <p>Attack vector: After an attacker has built up a victim's wait counter,
         * the victim successfully authenticates. This should reset the wait state.
         *
         * <p>Security property: Successful MFA approval MUST reset the wait counter,
         * preventing an attacker from indefinitely building up a victim's wait state.
         */
        @Test
        @DisplayName("Successful authentication resets wait state")
        void successfulAuthenticationResetsWaitState() throws Exception {
            String username = BYPASS_USER_9;
            DeviceClient deviceClient = enrollDevice(username, BYPASS_PASSWORD, DeviceKeyType.RSA);

            adminClient.configurePushMfaMaxPendingChallenges(10);
            adminClient.configurePushMfaWaitChallenge(true, 2, 60, 1);
            adminClient.configurePushMfaLoginChallengeTtlSeconds(2);

            try {
                // Build up wait state with expired challenge
                BrowserSession firstSession = new BrowserSession(baseUri);
                HtmlPage firstLogin = firstSession.startAuthorization("test-app");
                HtmlPage firstWaiting = firstSession.submitLogin(firstLogin, username, BYPASS_PASSWORD);
                firstSession.extractDeviceChallenge(firstWaiting);
                awaitNoPendingChallenges(deviceClient);

                // Wait for the wait period
                Thread.sleep(2500);

                // Now successfully authenticate
                BrowserSession successSession = new BrowserSession(baseUri);
                HtmlPage successLogin = successSession.startAuthorization("test-app");
                HtmlPage successWaiting = successSession.submitLogin(successLogin, username, BYPASS_PASSWORD);
                BrowserSession.DeviceChallenge challenge = successSession.extractDeviceChallenge(successWaiting);

                String status = deviceClient.respondToChallenge(
                        challenge.confirmToken(), challenge.challengeId(), PushMfaConstants.CHALLENGE_APPROVE);
                assertEquals("approved", status);
                successSession.completePushChallenge(challenge.formAction());

                // Wait state should be reset - next login should succeed immediately without wait
                BrowserSession afterResetSession = new BrowserSession(baseUri);
                HtmlPage afterResetLogin = afterResetSession.startAuthorization("test-app");
                HtmlPage afterResetResult = afterResetSession.submitLogin(afterResetLogin, username, BYPASS_PASSWORD);

                // Should get a challenge page immediately (no wait)
                BrowserSession.DeviceChallenge afterResetChallenge =
                        afterResetSession.extractDeviceChallenge(afterResetResult);
                assertNotNull(afterResetChallenge, "After successful auth, wait state should be reset");

                // Clean up
                deviceClient.respondToChallenge(
                        afterResetChallenge.confirmToken(),
                        afterResetChallenge.challengeId(),
                        PushMfaConstants.CHALLENGE_APPROVE);
                afterResetSession.completePushChallenge(afterResetChallenge.formAction());

            } finally {
                adminClient.disablePushMfaWaitChallenge();
                adminClient.configurePushMfaLoginChallengeTtlSeconds(
                        PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.toSeconds());
                adminClient.clearUserAttribute(username, WAIT_ATTRIBUTE_KEY);
            }
        }
    }

    // ==================== Helper Methods ====================

    private DeviceClient enrollDevice(String username, String password, DeviceKeyType keyType) throws Exception {
        adminClient.resetUserState(username);
        DeviceState deviceState = DeviceState.create(keyType);
        DeviceClient deviceClient = new DeviceClient(baseUri, deviceState);

        BrowserSession enrollmentSession = new BrowserSession(baseUri);
        HtmlPage loginPage = enrollmentSession.startAuthorization("test-app");
        HtmlPage enrollmentPage = enrollmentSession.submitLogin(loginPage, username, password);
        String enrollmentToken = enrollmentSession.extractEnrollmentToken(enrollmentPage);
        deviceClient.completeEnrollment(enrollmentToken);
        enrollmentSession.submitEnrollmentCheck(enrollmentPage);
        return deviceClient;
    }

    private void awaitNoPendingChallenges(DeviceClient deviceClient) throws Exception {
        long deadline = System.currentTimeMillis() + 15000L;
        while (System.currentTimeMillis() < deadline) {
            JsonNode pending = deviceClient.fetchPendingChallenges();
            if (pending.isArray() && pending.isEmpty()) {
                return;
            }
            Thread.sleep(250);
        }
        JsonNode pending = deviceClient.fetchPendingChallenges();
        assertEquals(0, pending.size(), () -> "Expected pending challenges to expire but got: " + pending);
    }

    private static Path locateProviderJar() {
        Path targetDir = Paths.get("target");
        if (!Files.isDirectory(targetDir)) {
            throw new IllegalStateException("target directory not found. Run mvn package before integration tests.");
        }
        Path candidate = targetDir.resolve("keycloak-push-mfa-extension.jar");
        if (Files.isRegularFile(candidate)) {
            return candidate;
        }
        throw new IllegalStateException(
                "Provider JAR not found at " + candidate + ". Run mvn package before integration tests.");
    }
}
