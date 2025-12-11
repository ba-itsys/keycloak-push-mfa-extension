package de.arbeitsagentur.keycloak.push.requiredaction;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.token.PushEnrollmentTokenBuilder;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.core.MultivaluedMap;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.time.Duration;
import org.apache.http.client.utils.URIBuilder;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

public class PushMfaRegisterRequiredAction implements RequiredActionProvider {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        // Handled by authenticator setRequiredActions.
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        PushChallengeStore store = new PushChallengeStore(context.getSession());
        PushChallenge challenge = ensureWatchableChallenge(
                context, authSession, store, fetchOrCreateChallenge(context, authSession, store, false));

        String enrollmentToken = PushEnrollmentTokenBuilder.build(
                context.getSession(),
                context.getRealm(),
                context.getUser(),
                challenge,
                context.getUriInfo().getBaseUri());

        LoginFormsProvider form = context.form();
        form.setAttribute("pushUsername", context.getUser().getUsername());
        form.setAttribute("enrollmentToken", enrollmentToken);
        form.setAttribute("qrPayload", enrollmentToken);
        form.setAttribute("pushQrUri", buildPushUri(resolveAppUniversalLink(context), enrollmentToken));
        form.setAttribute("enrollChallengeId", challenge.getId());
        form.setAttribute("pollingIntervalSeconds", 3);
        String eventsUrl = buildEnrollmentEventsUrl(context, challenge);
        if (eventsUrl != null) {
            form.setAttribute("enrollEventsUrl", eventsUrl);
        }
        context.challenge(form.createForm("push-register.ftl"));
    }

    @Override
    public void processAction(RequiredActionContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        PushChallengeStore store = new PushChallengeStore(context.getSession());

        boolean checkOnly = formData.containsKey("check");

        if (formData.containsKey("refresh")) {
            cleanupChallenge(authSession, store);
            requiredActionChallenge(context);
            return;
        }

        boolean hasCredential =
                !PushCredentialService.getActiveCredentials(context.getUser()).isEmpty();

        if (!hasCredential) {
            if (checkOnly) {
                requiredActionChallenge(context);
                return;
            }
            cleanupChallenge(authSession, store);
            PushChallenge challenge = ensureWatchableChallenge(
                    context, authSession, store, fetchOrCreateChallenge(context, authSession, store, false));
            String enrollmentToken = PushEnrollmentTokenBuilder.build(
                    context.getSession(),
                    context.getRealm(),
                    context.getUser(),
                    challenge,
                    context.getUriInfo().getBaseUri());

            LoginFormsProvider form = context.form().setError("push-mfa-registration-missing");
            form.setAttribute("pushUsername", context.getUser().getUsername());
            form.setAttribute("enrollmentToken", enrollmentToken);
            form.setAttribute("qrPayload", enrollmentToken);
            form.setAttribute("pushQrUri", buildPushUri(resolveAppUniversalLink(context), enrollmentToken));
            form.setAttribute("enrollChallengeId", challenge.getId());
            form.setAttribute("pollingIntervalSeconds", 5);
            String eventsUrl = buildEnrollmentEventsUrl(context, challenge);
            if (eventsUrl != null) {
                form.setAttribute("enrollEventsUrl", eventsUrl);
            }
            context.challenge(form.createForm("push-register.ftl"));
            return;
        }

        cleanupChallenge(authSession, store);
        context.success();
    }

    @Override
    public void close() {
        // no-op
    }

    private PushChallenge fetchOrCreateChallenge(
            RequiredActionContext context,
            AuthenticationSessionModel authSession,
            PushChallengeStore store,
            boolean forceNew) {
        Duration challengeTtl = resolveEnrollmentTtl(context);
        PushChallenge challenge = null;
        if (!forceNew) {
            String existingId = authSession.getAuthNote(PushMfaConstants.ENROLL_CHALLENGE_NOTE);
            if (existingId != null) {
                challenge = store.get(existingId)
                        .filter(c -> c.getStatus() == PushChallengeStatus.PENDING)
                        .orElse(null);
                if (challenge == null) {
                    store.remove(existingId);
                    authSession.removeAuthNote(PushMfaConstants.ENROLL_CHALLENGE_NOTE);
                }
            }
        }

        if (challenge == null) {
            byte[] nonceBytes = new byte[PushMfaConstants.NONCE_BYTES_SIZE];
            RANDOM.nextBytes(nonceBytes);
            String watchSecret = KeycloakModelUtils.generateId();
            challenge = store.create(
                    context.getRealm().getId(),
                    context.getUser().getId(),
                    nonceBytes,
                    PushChallenge.Type.ENROLLMENT,
                    challengeTtl,
                    null,
                    null,
                    watchSecret,
                    null);
            authSession.setAuthNote(PushMfaConstants.ENROLL_CHALLENGE_NOTE, challenge.getId());
        }

        return challenge;
    }

    private void cleanupChallenge(AuthenticationSessionModel authSession, PushChallengeStore store) {
        String challengeId = authSession.getAuthNote(PushMfaConstants.ENROLL_CHALLENGE_NOTE);
        if (challengeId != null) {
            store.remove(challengeId);
            authSession.removeAuthNote(PushMfaConstants.ENROLL_CHALLENGE_NOTE);
        }
        authSession.removeAuthNote(PushMfaConstants.ENROLL_SSE_TOKEN_NOTE);
    }

    private PushChallenge ensureWatchableChallenge(
            RequiredActionContext context,
            AuthenticationSessionModel authSession,
            PushChallengeStore store,
            PushChallenge challenge) {
        PushChallenge ensured = challenge;
        if (ensured == null || StringUtil.isBlank(ensured.getWatchSecret())) {
            cleanupChallenge(authSession, store);
            ensured = fetchOrCreateChallenge(context, authSession, store, true);
        }
        if (!StringUtil.isBlank(ensured.getWatchSecret())) {
            authSession.setAuthNote(PushMfaConstants.ENROLL_SSE_TOKEN_NOTE, ensured.getWatchSecret());
        }
        return ensured;
    }

    private String buildPushUri(String appUniversalLink, String enrollmentToken) {
        if (StringUtil.isBlank(appUniversalLink)) {
            return enrollmentToken;
        }
        try {
            URIBuilder uriBuilder = new URIBuilder(appUniversalLink);
            uriBuilder.addParameter("token", enrollmentToken);
            return uriBuilder.toString();
        } catch (URISyntaxException e) {
            // noop - fallback to just the token
        }
        return enrollmentToken;
    }

    private String buildEnrollmentEventsUrl(RequiredActionContext context, PushChallenge challenge) {
        String watchSecret = challenge.getWatchSecret();
        if (StringUtil.isBlank(watchSecret)) {
            return null;
        }
        return context.getUriInfo()
                .getBaseUriBuilder()
                .path("realms")
                .path(context.getRealm().getName())
                .path("push-mfa")
                .path("enroll")
                .path("challenges")
                .path(challenge.getId())
                .path("events")
                .queryParam("secret", watchSecret)
                .build()
                .toString();
    }

    private Duration resolveEnrollmentTtl(RequiredActionContext context) {
        RequiredActionConfigModel config = context.getConfig();
        if (config == null || config.getConfig() == null) {
            return PushMfaConstants.DEFAULT_ENROLLMENT_CHALLENGE_TTL;
        }
        String value = config.getConfig().get(PushMfaConstants.ENROLLMENT_CHALLENGE_TTL_CONFIG);
        if (StringUtil.isBlank(value)) {
            return PushMfaConstants.DEFAULT_ENROLLMENT_CHALLENGE_TTL;
        }
        try {
            long seconds = Long.parseLong(value.trim());
            return seconds > 0 ? Duration.ofSeconds(seconds) : PushMfaConstants.DEFAULT_ENROLLMENT_CHALLENGE_TTL;
        } catch (NumberFormatException ex) {
            return PushMfaConstants.DEFAULT_ENROLLMENT_CHALLENGE_TTL;
        }
    }

    private String resolveAppUniversalLink(RequiredActionContext context) {
        RequiredActionConfigModel config = context.getConfig();
        if (config == null || config.getConfig() == null) {
            return PushMfaConstants.DEFAULT_APP_UNIVERSAL_LINK + "enroll";
        }
        String value = config.getConfig().get(PushMfaConstants.APP_UNIVERSAL_LINK_CONFIG);
        if (StringUtil.isBlank(value)) {
            return PushMfaConstants.DEFAULT_APP_UNIVERSAL_LINK + "enroll";
        }
        return value;
    }
}
