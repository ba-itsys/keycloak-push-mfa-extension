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

package de.arbeitsagentur.keycloak.push.token;

import de.arbeitsagentur.keycloak.push.util.PushMfaStringUtil;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.utils.StringUtil;

/**
 * Stores short-lived enrollment request handles used by the optional {@code request_uri} flow.
 *
 * <p>The handle is an opaque random capability URL component. It resolves to the minimum server
 * state required to rebuild the signed enrollment token on demand.
 */
public final class PushEnrollmentRequestStore {

    private static final String REQUEST_PREFIX = "push-mfa:enroll-request:";
    private static final String KEY_REALM_ID = "realmId";
    private static final String KEY_USER_ID = "userId";
    private static final String KEY_CHALLENGE_ID = "challengeId";

    private final SingleUseObjectProvider singleUse;

    public PushEnrollmentRequestStore(KeycloakSession session) {
        this.singleUse = Objects.requireNonNull(session.singleUseObjects());
    }

    public void store(String requestHandle, Duration ttl, Entry entry) {
        if (StringUtil.isBlank(requestHandle) || ttl == null || entry == null) {
            return;
        }
        long ttlSeconds = Math.max(1L, ttl.toSeconds());
        singleUse.put(
                requestKey(requestHandle),
                ttlSeconds,
                Map.of(
                        KEY_REALM_ID, PushMfaStringUtil.emptyIfNull(entry.realmId()),
                        KEY_USER_ID, PushMfaStringUtil.emptyIfNull(entry.userId()),
                        KEY_CHALLENGE_ID, PushMfaStringUtil.emptyIfNull(entry.challengeId())));
    }

    public Entry resolve(String requestHandle) {
        if (StringUtil.isBlank(requestHandle)) {
            return null;
        }
        Map<String, String> entry = singleUse.get(requestKey(requestHandle));
        if (entry == null) {
            return null;
        }
        String realmId = PushMfaStringUtil.blankToNull(entry.get(KEY_REALM_ID));
        String userId = PushMfaStringUtil.blankToNull(entry.get(KEY_USER_ID));
        String challengeId = PushMfaStringUtil.blankToNull(entry.get(KEY_CHALLENGE_ID));
        if (realmId == null || userId == null || challengeId == null) {
            singleUse.remove(requestKey(requestHandle));
            return null;
        }
        return new Entry(realmId, userId, challengeId);
    }

    public void remove(String requestHandle) {
        if (StringUtil.isBlank(requestHandle)) {
            return;
        }
        singleUse.remove(requestKey(requestHandle));
    }

    private static String requestKey(String requestHandle) {
        return REQUEST_PREFIX + requestHandle;
    }

    public record Entry(String realmId, String userId, String challengeId) {}
}
