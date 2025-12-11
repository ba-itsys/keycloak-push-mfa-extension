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
