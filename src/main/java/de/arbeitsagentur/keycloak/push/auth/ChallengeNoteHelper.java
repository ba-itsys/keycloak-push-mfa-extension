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

package de.arbeitsagentur.keycloak.push.auth;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

/**
 * Handles storing and reading challenge-related notes.
 *
 * <p>We write the challenge id to both auth notes and client notes because Keycloak can rebuild or
 * restart auth sessions and drop auth notes, while client notes survive the restart flow. Reading
 * prefers auth notes (server-side) and falls back to client notes so the challenge id is preserved
 * even if the session code changes mid-flow. The watch secret stays only in auth notes to avoid
 * sending it back to the browser.</p>
 */
public final class ChallengeNoteHelper {

    private ChallengeNoteHelper() {}

    public static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (!StringUtil.isBlank(value)) {
                return value;
            }
        }
        return null;
    }

    public static void storeChallengeId(AuthenticationSessionModel session, String challengeId) {
        if (session == null || StringUtil.isBlank(challengeId)) {
            return;
        }
        session.setAuthNote(PushMfaConstants.CHALLENGE_NOTE, challengeId);
        session.setClientNote(PushMfaConstants.CHALLENGE_NOTE, challengeId);
    }

    public static String readChallengeId(AuthenticationSessionModel session) {
        if (session == null) {
            return null;
        }
        return firstNonBlank(
                session.getAuthNote(PushMfaConstants.CHALLENGE_NOTE),
                session.getClientNote(PushMfaConstants.CHALLENGE_NOTE));
    }

    public static void storeWatchSecret(AuthenticationSessionModel session, String watchSecret) {
        if (session == null || StringUtil.isBlank(watchSecret)) {
            return;
        }
        session.setAuthNote(PushMfaConstants.CHALLENGE_WATCH_SECRET_NOTE, watchSecret);
    }

    public static String readWatchSecret(AuthenticationSessionModel session) {
        if (session == null) {
            return null;
        }
        return session.getAuthNote(PushMfaConstants.CHALLENGE_WATCH_SECRET_NOTE);
    }

    public static void clear(AuthenticationSessionModel session) {
        if (session == null) {
            return;
        }
        session.removeAuthNote(PushMfaConstants.CHALLENGE_NOTE);
        session.removeAuthNote(PushMfaConstants.CHALLENGE_WATCH_SECRET_NOTE);
        session.removeClientNote(PushMfaConstants.CHALLENGE_NOTE);
    }
}
