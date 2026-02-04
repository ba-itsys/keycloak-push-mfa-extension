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

package de.arbeitsagentur.keycloak.push.spi.waitchallenge;

import de.arbeitsagentur.keycloak.push.challenge.WaitChallengeState;
import de.arbeitsagentur.keycloak.push.spi.WaitChallengeStateProvider;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.utils.StringUtil;

/**
 * Wait challenge state provider using Keycloak's {@link SingleUseObjectProvider}.
 *
 * <p>This implementation stores wait state with automatic TTL-based expiration.
 * The state is stored in-memory and will be lost on server restart unless
 * an external Infinispan store is configured.
 */
public class SingleUseObjectWaitChallengeStateProvider implements WaitChallengeStateProvider {

    private static final String KEY_PREFIX = "push-mfa:wait-state:";
    private static final String FIRST_UNAPPROVED_AT = "firstUnapprovedAt";
    private static final String LAST_CHALLENGE_AT = "lastChallengeAt";
    private static final String CONSECUTIVE_UNAPPROVED = "consecutiveUnapproved";
    private static final String WAIT_UNTIL = "waitUntil";

    private final SingleUseObjectProvider singleUse;

    public SingleUseObjectWaitChallengeStateProvider(KeycloakSession session) {
        this.singleUse = Objects.requireNonNull(session.singleUseObjects());
    }

    @Override
    public Optional<WaitChallengeState> get(String realmId, String userId, Duration resetPeriod) {
        Map<String, String> data = singleUse.get(key(realmId, userId));
        if (data == null) {
            return Optional.empty();
        }

        WaitChallengeState state = fromMap(data);
        if (state == null) {
            singleUse.remove(key(realmId, userId));
            return Optional.empty();
        }

        // Check if state has expired based on reset period
        if (state.isExpired(Instant.now(), resetPeriod)) {
            singleUse.remove(key(realmId, userId));
            return Optional.empty();
        }

        return Optional.of(state);
    }

    @Override
    public void recordChallengeCreated(
            String realmId, String userId, Duration baseWait, Duration maxWait, Duration resetPeriod) {
        Instant now = Instant.now();
        Map<String, String> existingData = singleUse.get(key(realmId, userId));
        WaitChallengeState existing = existingData != null ? fromMap(existingData) : null;

        int newCount;
        Instant firstUnapprovedAt;

        if (existing == null || existing.isExpired(now, resetPeriod)) {
            // Start fresh
            newCount = 1;
            firstUnapprovedAt = now;
        } else {
            // Increment existing
            newCount = existing.consecutiveUnapproved() + 1;
            firstUnapprovedAt = existing.firstUnapprovedAt();
        }

        Duration waitDuration = WaitChallengeState.calculateNextWait(newCount, baseWait, maxWait);
        Instant waitUntil = now.plus(waitDuration);

        Map<String, String> data = new HashMap<>();
        data.put(FIRST_UNAPPROVED_AT, firstUnapprovedAt.toString());
        data.put(LAST_CHALLENGE_AT, now.toString());
        data.put(CONSECUTIVE_UNAPPROVED, String.valueOf(newCount));
        data.put(WAIT_UNTIL, waitUntil.toString());

        long ttlSeconds = Math.max(1L, resetPeriod.toSeconds());
        singleUse.put(key(realmId, userId), ttlSeconds, data);
    }

    @Override
    public void reset(String realmId, String userId) {
        singleUse.remove(key(realmId, userId));
    }

    @Override
    public void close() {
        // no-op
    }

    private String key(String realmId, String userId) {
        return KEY_PREFIX + realmId + ":" + userId;
    }

    private WaitChallengeState fromMap(Map<String, String> data) {
        String firstUnapprovedAtStr = data.get(FIRST_UNAPPROVED_AT);
        String lastChallengeAtStr = data.get(LAST_CHALLENGE_AT);
        String consecutiveUnapprovedStr = data.get(CONSECUTIVE_UNAPPROVED);
        String waitUntilStr = data.get(WAIT_UNTIL);

        if (StringUtil.isBlank(firstUnapprovedAtStr)
                || StringUtil.isBlank(lastChallengeAtStr)
                || StringUtil.isBlank(consecutiveUnapprovedStr)
                || StringUtil.isBlank(waitUntilStr)) {
            return null;
        }

        try {
            return new WaitChallengeState(
                    Instant.parse(firstUnapprovedAtStr),
                    Instant.parse(lastChallengeAtStr),
                    Integer.parseInt(consecutiveUnapprovedStr),
                    Instant.parse(waitUntilStr));
        } catch (Exception e) {
            return null;
        }
    }
}
