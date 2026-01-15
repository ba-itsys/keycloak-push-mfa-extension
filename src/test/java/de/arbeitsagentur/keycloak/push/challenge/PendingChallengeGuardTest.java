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

package de.arbeitsagentur.keycloak.push.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;

class PendingChallengeGuardTest {

    private final Instant now = Instant.now();

    @Test
    void removesStaleChallengesAndKeepsActive() {
        PushChallengeStore store = mock(PushChallengeStore.class);
        PushChallenge active = challenge("active", "root-b");
        PushChallenge missingSession = challenge("missing-session", "root-c");
        when(store.findPendingAuthenticationForUser("realm", "user")).thenReturn(List.of(active, missingSession));

        PendingChallengeGuard guard = new PendingChallengeGuard(store);
        PendingChallengeGuard.PendingCheckResult result =
                guard.cleanAndCount("realm", "user", "root-a", null, matches(active), alwaysTrue());

        assertEquals(1, result.pending().size());
        assertEquals(active.getId(), result.pending().get(0).getId());
        assertEquals(1, result.pendingCount());
        verify(store).remove(missingSession.getId());
    }

    @Test
    void removesChallengesFromSameRootAndUnknownRoot() {
        PushChallengeStore store = mock(PushChallengeStore.class);
        PushChallenge sameRoot = challenge("same-root", "root-a");
        PushChallenge unknownRoot = challenge("unknown-root", null);
        when(store.findPendingAuthenticationForUser("realm", "user")).thenReturn(List.of(sameRoot, unknownRoot));

        PendingChallengeGuard guard = new PendingChallengeGuard(store);
        PendingChallengeGuard.PendingCheckResult result =
                guard.cleanAndCount("realm", "user", "root-a", null, alwaysTrue(), alwaysTrue());

        assertTrue(result.pending().isEmpty());
        assertEquals(0, result.pendingCount());
        verify(store).remove(sameRoot.getId());
        verify(store).remove(unknownRoot.getId());
    }

    @Test
    void discountsCurrentAuthSessionChallenge() {
        PushChallengeStore store = mock(PushChallengeStore.class);
        PushChallenge current = challenge("current", "root-b");
        when(store.findPendingAuthenticationForUser("realm", "user")).thenReturn(List.of(current));

        PendingChallengeGuard guard = new PendingChallengeGuard(store);
        PendingChallengeGuard.PendingCheckResult result =
                guard.cleanAndCount("realm", "user", "root-a", current.getId(), alwaysTrue(), alwaysTrue());

        assertTrue(result.pending().isEmpty());
        assertEquals(0, result.pendingCount());
        verify(store).remove(current.getId());
    }

    private PushChallenge challenge(String id, String rootSessionId) {
        return new PushChallenge(
                id,
                "realm",
                "user",
                new byte[0],
                "cred",
                "client",
                "watch",
                rootSessionId,
                now.plusSeconds(120),
                PushChallenge.Type.AUTHENTICATION,
                PushChallengeStatus.PENDING,
                now,
                null);
    }

    private Predicate<PushChallenge> alwaysTrue() {
        return challenge -> true;
    }

    private Predicate<PushChallenge> matches(PushChallenge expected) {
        return challenge -> challenge == expected;
    }
}
