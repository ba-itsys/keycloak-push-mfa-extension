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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import org.keycloak.utils.StringUtil;

public class PendingChallengeGuard {

    private final PushChallengeStore challengeStore;

    public PendingChallengeGuard(PushChallengeStore challengeStore) {
        this.challengeStore = Objects.requireNonNull(challengeStore);
    }

    public PendingCheckResult cleanAndCount(
            String realmId,
            String userId,
            String rootSessionId,
            String authSessionChallengeId,
            Predicate<PushChallenge> activeSessionPredicate,
            Predicate<PushChallenge> credentialExistsPredicate) {
        List<PushChallenge> pending = new ArrayList<>(challengeStore.findPendingAuthenticationForUser(realmId, userId));
        pending.removeIf(challenge -> shouldRemove(
                challenge, rootSessionId, authSessionChallengeId, activeSessionPredicate, credentialExistsPredicate));

        int pendingCount = pending.size();
        if (authSessionChallengeId != null && pendingCount > 0) {
            pendingCount--;
        }

        return new PendingCheckResult(pendingCount, pending);
    }

    private boolean shouldRemove(
            PushChallenge challenge,
            String rootSessionId,
            String authSessionChallengeId,
            Predicate<PushChallenge> activeSessionPredicate,
            Predicate<PushChallenge> credentialExistsPredicate) {
        boolean missingSession = !activeSessionPredicate.test(challenge);
        boolean missingCredential = !credentialExistsPredicate.test(challenge);
        boolean sameOrUnknownRoot = isSameOrUnknownRoot(challenge, rootSessionId);
        boolean matchesAuthSession = authSessionChallengeId != null && authSessionChallengeId.equals(challenge.getId());
        if (missingSession || missingCredential || sameOrUnknownRoot || matchesAuthSession) {
            challengeStore.remove(challenge.getId());
            return true;
        }
        return false;
    }

    private boolean isSameOrUnknownRoot(PushChallenge challenge, String rootSessionId) {
        String challengeRoot = challenge.getRootSessionId();
        if (StringUtil.isBlank(challengeRoot)) {
            return true;
        }
        return rootSessionId != null && rootSessionId.equals(challengeRoot);
    }

    public record PendingCheckResult(int pendingCount, List<PushChallenge> pending) {}
}
