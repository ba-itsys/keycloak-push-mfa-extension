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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.push.challenge.WaitChallengeState;
import de.arbeitsagentur.keycloak.push.spi.WaitChallengeStateProvider;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.utils.StringUtil;

/**
 * Wait challenge state provider using Keycloak user attributes.
 *
 * <p>This implementation persists wait state in the database via user attributes.
 * State survives server restarts but requires a database write on each update.
 * Expired state is cleaned up on-demand when read.
 */
public class UserAttributeWaitChallengeStateProvider implements WaitChallengeStateProvider {

    private static final String ATTRIBUTE_KEY = "push-mfa-wait-state";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final KeycloakSession session;

    public UserAttributeWaitChallengeStateProvider(KeycloakSession session) {
        this.session = Objects.requireNonNull(session);
    }

    @Override
    public Optional<WaitChallengeState> get(String realmId, String userId, Duration resetPeriod) {
        UserModel user = resolveUser(realmId, userId);
        if (user == null) {
            return Optional.empty();
        }

        String json = user.getFirstAttribute(ATTRIBUTE_KEY);
        if (StringUtil.isBlank(json)) {
            return Optional.empty();
        }

        WaitChallengeState state = fromJson(json);
        if (state == null) {
            // Invalid data, clean up
            user.removeAttribute(ATTRIBUTE_KEY);
            return Optional.empty();
        }

        // Check if state has expired - on-demand cleanup
        if (state.isExpired(Instant.now(), resetPeriod)) {
            user.removeAttribute(ATTRIBUTE_KEY);
            return Optional.empty();
        }

        return Optional.of(state);
    }

    @Override
    public void recordChallengeCreated(
            String realmId, String userId, Duration baseWait, Duration maxWait, Duration resetPeriod) {
        UserModel user = resolveUser(realmId, userId);
        if (user == null) {
            return;
        }

        Instant now = Instant.now();
        String existingJson = user.getFirstAttribute(ATTRIBUTE_KEY);
        WaitChallengeState existing = StringUtil.isBlank(existingJson) ? null : fromJson(existingJson);

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

        WaitChallengeState newState = new WaitChallengeState(firstUnapprovedAt, now, newCount, waitUntil);
        String json = toJson(newState);
        if (json != null) {
            user.setSingleAttribute(ATTRIBUTE_KEY, json);
        }
    }

    @Override
    public void reset(String realmId, String userId) {
        UserModel user = resolveUser(realmId, userId);
        if (user != null) {
            user.removeAttribute(ATTRIBUTE_KEY);
        }
    }

    @Override
    public void close() {
        // no-op
    }

    private UserModel resolveUser(String realmId, String userId) {
        RealmModel realm = session.realms().getRealm(realmId);
        if (realm == null) {
            return null;
        }
        return session.users().getUserById(realm, userId);
    }

    private WaitChallengeState fromJson(String json) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> data = MAPPER.readValue(json, Map.class);
            String firstUnapprovedAt = (String) data.get("firstUnapprovedAt");
            String lastChallengeAt = (String) data.get("lastChallengeAt");
            Object consecutiveUnapprovedObj = data.get("consecutiveUnapproved");
            String waitUntil = (String) data.get("waitUntil");

            if (firstUnapprovedAt == null
                    || lastChallengeAt == null
                    || consecutiveUnapprovedObj == null
                    || waitUntil == null) {
                return null;
            }

            int consecutiveUnapproved;
            if (consecutiveUnapprovedObj instanceof Number) {
                consecutiveUnapproved = ((Number) consecutiveUnapprovedObj).intValue();
            } else {
                consecutiveUnapproved = Integer.parseInt(consecutiveUnapprovedObj.toString());
            }

            return new WaitChallengeState(
                    Instant.parse(firstUnapprovedAt),
                    Instant.parse(lastChallengeAt),
                    consecutiveUnapproved,
                    Instant.parse(waitUntil));
        } catch (Exception e) {
            return null;
        }
    }

    private String toJson(WaitChallengeState state) {
        try {
            Map<String, Object> data = Map.of(
                    "firstUnapprovedAt", state.firstUnapprovedAt().toString(),
                    "lastChallengeAt", state.lastChallengeAt().toString(),
                    "consecutiveUnapproved", state.consecutiveUnapproved(),
                    "waitUntil", state.waitUntil().toString());
            return MAPPER.writeValueAsString(data);
        } catch (JsonProcessingException e) {
            return null;
        }
    }
}
