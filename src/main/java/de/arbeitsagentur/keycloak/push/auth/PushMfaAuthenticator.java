package de.arbeitsagentur.keycloak.push.auth;

import de.arbeitsagentur.keycloak.push.challenge.PendingChallengeGuard;
import de.arbeitsagentur.keycloak.push.challenge.PendingChallengeGuard.PendingCheckResult;
import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.service.PushNotificationService;
import de.arbeitsagentur.keycloak.push.token.PushConfirmTokenBuilder;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

public class PushMfaAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(PushMfaAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String requestChallengeId = ChallengeNoteHelper.firstNonBlank(form.getFirst("challengeId"));
        boolean isRefresh = form.containsKey("refresh") || form.containsKey("cancel");
        if (!StringUtil.isBlank(requestChallengeId)) {
            ChallengeNoteHelper.storeChallengeId(authSession, requestChallengeId);
            action(context);
            return;
        }
        if (isRefresh && ChallengeNoteHelper.readChallengeId(authSession) != null) {
            action(context);
            return;
        }
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        Duration loginChallengeTtl = parseDurationSeconds(
                config, PushMfaConstants.LOGIN_CHALLENGE_TTL_CONFIG, PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL);
        int maxPendingChallenges = parsePositiveInt(
                config,
                PushMfaConstants.MAX_PENDING_AUTH_CHALLENGES_CONFIG,
                PushMfaConstants.DEFAULT_MAX_PENDING_AUTH_CHALLENGES);

        List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(context.getUser());
        if (credentials.isEmpty()) {
            LOG.infof(
                    "User %s attempted push MFA without registered device",
                    context.getUser().getId());
            context.success();
            return;
        }

        CredentialModel credential = credentials.get(0);
        PushCredentialData credentialData = PushCredentialService.readCredentialData(credential);
        if (credentialData == null || credentialData.getCredentialId() == null) {
            LOG.warn("Push credential missing credential id; skipping push MFA");
            context.success();
            return;
        }

        PushChallengeStore challengeStore = new PushChallengeStore(context.getSession());
        String rootSessionId = context.getAuthenticationSession().getParentSession() != null
                ? context.getAuthenticationSession().getParentSession().getId()
                : null;
        String authSessionChallenge = ChallengeNoteHelper.readChallengeId(authSession);
        PendingChallengeGuard guard = new PendingChallengeGuard(challengeStore);
        PendingCheckResult pending = guard.cleanAndCount(
                context.getRealm().getId(),
                context.getUser().getId(),
                rootSessionId,
                authSessionChallenge,
                challenge -> isAuthenticationSessionActive(context, challenge),
                challenge -> resolveCredentialForChallenge(context.getUser(), challenge) != null);

        if (pending.pendingCount() >= maxPendingChallenges && authSessionChallenge == null && !isRefresh) {
            LOG.warnf(
                    "User %s already has %d pending push challenges (limit %d); refusing new one. method=%s,authNote=%s,rootSession=%s,Pending=%s",
                    context.getUser().getId(),
                    pending.pendingCount(),
                    maxPendingChallenges,
                    context.getHttpRequest().getHttpMethod(),
                    authSessionChallenge,
                    rootSessionId,
                    pending.pending().stream()
                            .map(ch -> ch.getId() + "/" + ch.getRootSessionId())
                            .toList());
            context.failureChallenge(
                    AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR,
                    context.form()
                            .setError("push-mfa-too-many-challenges")
                            .createErrorPage(Response.Status.TOO_MANY_REQUESTS));
            return;
        }
        ClientModel client = context.getAuthenticationSession().getClient();
        String clientId = client != null ? client.getClientId() : null;

        IssuedChallenge issued = issueNewChallenge(
                context, challengeStore, credentialData, credential, loginChallengeTtl, clientId, rootSessionId);
        showWaitingForm(context, issued.challenge(), credentialData, issued.confirmToken());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        Duration loginChallengeTtl = parseDurationSeconds(
                config, PushMfaConstants.LOGIN_CHALLENGE_TTL_CONFIG, PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL);
        int maxPendingChallenges = parsePositiveInt(
                config,
                PushMfaConstants.MAX_PENDING_AUTH_CHALLENGES_CONFIG,
                PushMfaConstants.DEFAULT_MAX_PENDING_AUTH_CHALLENGES);
        PushChallengeStore challengeStore = new PushChallengeStore(context.getSession());
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String challengeId = ChallengeNoteHelper.firstNonBlank(
                ChallengeNoteHelper.readChallengeId(authSession), form.getFirst("challengeId"));

        if (challengeId == null) {
            context.failureChallenge(
                    AuthenticationFlowError.INTERNAL_ERROR,
                    context.form()
                            .setError("push-mfa-missing-challenge")
                            .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            return;
        }

        boolean refreshRequested = form.containsKey("refresh");
        boolean cancelRequested = form.containsKey("cancel");
        if (cancelRequested) {
            challengeStore.resolve(challengeId, PushChallengeStatus.DENIED);
            challengeStore.remove(challengeId);
            ChallengeNoteHelper.clear(authSession);
            context.forkWithErrorMessage(new FormMessage("push-mfa-cancelled-message"));
            return;
        }

        Optional<PushChallenge> challenge = challengeStore.get(challengeId);
        if (challenge.isEmpty()) {
            context.failureChallenge(
                    AuthenticationFlowError.EXPIRED_CODE,
                    context.form().setError("push-mfa-expired").createForm("push-expired.ftl"));
            ChallengeNoteHelper.clear(authSession);
            return;
        }

        PushChallenge current = challenge.get();
        if (refreshRequested && current.getStatus() == PushChallengeStatus.PENDING) {
            challengeStore.removeWithoutIndex(challengeId);
            ChallengeNoteHelper.clear(authSession);

            String rootSessionId = authSession.getParentSession() != null
                    ? authSession.getParentSession().getId()
                    : null;
            PendingChallengeGuard guard = new PendingChallengeGuard(challengeStore);
            PendingCheckResult pending = guard.cleanAndCount(
                    context.getRealm().getId(),
                    context.getUser().getId(),
                    rootSessionId,
                    challengeId,
                    ch -> isAuthenticationSessionActive(context, ch),
                    ch -> resolveCredentialForChallenge(context.getUser(), ch) != null);
            if (pending.pendingCount() >= maxPendingChallenges) {
                context.failureChallenge(
                        AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR,
                        context.form()
                                .setError("push-mfa-too-many-challenges")
                                .createErrorPage(Response.Status.TOO_MANY_REQUESTS));
                return;
            }

            List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(context.getUser());
            if (credentials.isEmpty()) {
                context.success();
                return;
            }
            CredentialModel credential = credentials.get(0);
            PushCredentialData credentialData = PushCredentialService.readCredentialData(credential);
            if (credentialData == null || credentialData.getCredentialId() == null) {
                context.success();
                return;
            }

            ClientModel client = authSession.getClient();
            String clientId = client != null ? client.getClientId() : null;
            IssuedChallenge issued = issueNewChallenge(
                    context, challengeStore, credentialData, credential, loginChallengeTtl, clientId, rootSessionId);
            showWaitingForm(context, issued.challenge(), credentialData, issued.confirmToken());
            return;
        }
        switch (current.getStatus()) {
            case APPROVED -> {
                challengeStore.remove(challengeId);
                ChallengeNoteHelper.clear(authSession);
                context.success();
            }
            case DENIED -> {
                challengeStore.remove(challengeId);
                ChallengeNoteHelper.clear(authSession);
                context.failureChallenge(
                        AuthenticationFlowError.INVALID_CREDENTIALS,
                        context.form().setError("push-mfa-denied").createForm("push-denied.ftl"));
            }
            case EXPIRED -> {
                challengeStore.remove(challengeId);
                ChallengeNoteHelper.clear(authSession);
                context.failureChallenge(
                        AuthenticationFlowError.EXPIRED_CODE,
                        context.form().setError("push-mfa-expired").createForm("push-expired.ftl"));
            }
            case PENDING -> {
                CredentialModel credentialModel = resolveCredentialForChallenge(context.getUser(), current);
                PushCredentialData credentialData =
                        credentialModel == null ? null : PushCredentialService.readCredentialData(credentialModel);
                String clientId = current.getClientId();
                String clientDisplayName = resolveClientDisplayName(context, clientId);
                String confirmToken =
                        (credentialModel == null || credentialData == null || credentialData.getCredentialId() == null)
                                ? null
                                : PushConfirmTokenBuilder.build(
                                        context.getSession(),
                                        context.getRealm(),
                                        credentialData.getCredentialId(),
                                        current.getId(),
                                        current.getExpiresAt(),
                                        context.getUriInfo().getBaseUri());

                showWaitingForm(context, current, credentialData, confirmToken);
            }
            default -> throw new IllegalStateException("Unhandled push challenge status: " + current.getStatus());
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return !PushCredentialService.getActiveCredentials(user).isEmpty();
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        if (!PushCredentialService.getActiveCredentials(user).isEmpty()) {
            return;
        }

        boolean alreadyRequired = user.getRequiredActionsStream().anyMatch(PushMfaConstants.REQUIRED_ACTION_ID::equals);
        if (!alreadyRequired) {
            user.addRequiredAction(PushMfaConstants.REQUIRED_ACTION_ID);
        }
    }

    @Override
    public void close() {
        // no-op
    }

    private CredentialModel resolveCredentialForChallenge(UserModel user, PushChallenge challenge) {
        if (challenge.getCredentialId() != null) {
            CredentialModel byId = PushCredentialService.getCredentialById(user, challenge.getCredentialId());
            if (byId != null) {
                return byId;
            }
            LOG.warnf(
                    "Credential %s referenced by challenge %s not found for user %s",
                    challenge.getCredentialId(), challenge.getId(), user.getId());
        }
        List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(user);
        return credentials.isEmpty() ? null : credentials.get(0);
    }

    private boolean isAuthenticationSessionActive(AuthenticationFlowContext context, PushChallenge challenge) {
        String rootSession = challenge.getRootSessionId();
        if (StringUtil.isBlank(rootSession)) {
            return true;
        }
        return context.getSession()
                        .authenticationSessions()
                        .getRootAuthenticationSession(context.getRealm(), rootSession)
                != null;
    }

    private IssuedChallenge issueNewChallenge(
            AuthenticationFlowContext context,
            PushChallengeStore challengeStore,
            PushCredentialData credentialData,
            CredentialModel credential,
            Duration challengeTtl,
            String clientId,
            String rootSessionId) {
        String watchSecret = KeycloakModelUtils.generateId();
        PushChallenge pushChallenge = challengeStore.create(
                context.getRealm().getId(),
                context.getUser().getId(),
                new byte[0],
                PushChallenge.Type.AUTHENTICATION,
                challengeTtl,
                credential.getId(),
                clientId,
                watchSecret,
                rootSessionId);

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        ChallengeNoteHelper.storeChallengeId(authSession, pushChallenge.getId());
        ChallengeNoteHelper.storeWatchSecret(authSession, watchSecret);

        String confirmToken = PushConfirmTokenBuilder.build(
                context.getSession(),
                context.getRealm(),
                credentialData.getCredentialId(),
                pushChallenge.getId(),
                pushChallenge.getExpiresAt(),
                context.getUriInfo().getBaseUri());

        LOG.debugf(
                "Push message prepared {version=%d,type=%d,credentialId=%s}",
                PushMfaConstants.PUSH_MESSAGE_VERSION,
                PushMfaConstants.PUSH_MESSAGE_TYPE,
                credentialData.getCredentialId());

        PushNotificationService.notifyDevice(
                context.getSession(),
                context.getRealm(),
                context.getUser(),
                clientId,
                confirmToken,
                credentialData.getCredentialId(),
                pushChallenge.getId(),
                credentialData.getPushProviderType(),
                credentialData.getPushProviderId());

        return new IssuedChallenge(pushChallenge, confirmToken);
    }

    private void showWaitingForm(
            AuthenticationFlowContext context,
            PushChallenge challenge,
            PushCredentialData credentialData,
            String confirmToken) {
        String challengeId = challenge != null ? challenge.getId() : null;
        String watchSecret = challenge != null ? challenge.getWatchSecret() : null;
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        if (StringUtil.isBlank(watchSecret) && authSession != null) {
            watchSecret = ChallengeNoteHelper.readWatchSecret(authSession);
        }

        context.form()
                .setAttribute("challengeId", challengeId)
                .setAttribute("pollingIntervalSeconds", 5)
                .setAttribute("pushUsername", context.getUser().getUsername())
                .setAttribute("pushConfirmToken", confirmToken)
                .setAttribute("pushCredentialId", credentialData != null ? credentialData.getCredentialId() : null)
                .setAttribute("pushMessageVersion", String.valueOf(PushMfaConstants.PUSH_MESSAGE_VERSION))
                .setAttribute("pushMessageType", String.valueOf(PushMfaConstants.PUSH_MESSAGE_TYPE))
                .setAttribute("appUniversalLink", resolveAppUniversalLink(context));

        String watchUrl = buildChallengeWatchUrl(context, challengeId, watchSecret);
        if (watchUrl != null) {
            context.form().setAttribute("pushChallengeWatchUrl", watchUrl);
        }

        context.challenge(context.form().createForm("push-wait.ftl"));
    }

    private String buildChallengeWatchUrl(AuthenticationFlowContext context, String challengeId, String watchSecret) {
        if (StringUtil.isBlank(challengeId) || StringUtil.isBlank(watchSecret)) {
            return null;
        }
        UriBuilder builder = context.getUriInfo()
                .getBaseUriBuilder()
                .path("realms")
                .path(context.getRealm().getName())
                .path("push-mfa")
                .path("login")
                .path("challenges")
                .path(challengeId)
                .path("events")
                .queryParam("secret", watchSecret);
        return builder.build().toString();
    }

    private String resolveClientDisplayName(AuthenticationFlowContext context, String clientId) {
        if (clientId == null) {
            return null;
        }
        ClientModel byClientId = context.getSession().clients().getClientByClientId(context.getRealm(), clientId);
        return extractClientDisplayName(byClientId);
    }

    private String extractClientDisplayName(ClientModel client) {
        if (client == null) {
            return null;
        }
        String name = client.getName();
        if (StringUtil.isBlank(name)) {
            return null;
        }
        return name;
    }

    private Duration parseDurationSeconds(AuthenticatorConfigModel config, String key, Duration defaultValue) {
        if (config == null || config.getConfig() == null) {
            return defaultValue;
        }
        String value = config.getConfig().get(key);
        if (StringUtil.isBlank(value)) {
            return defaultValue;
        }
        try {
            long seconds = Long.parseLong(value.trim());
            return seconds > 0 ? Duration.ofSeconds(seconds) : defaultValue;
        } catch (NumberFormatException ex) {
            return defaultValue;
        }
    }

    private int parsePositiveInt(AuthenticatorConfigModel config, String key, int defaultValue) {
        if (config == null || config.getConfig() == null) {
            return defaultValue;
        }
        String value = config.getConfig().get(key);
        if (StringUtil.isBlank(value)) {
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            return parsed > 0 ? parsed : defaultValue;
        } catch (NumberFormatException ex) {
            return defaultValue;
        }
    }

    private String resolveAppUniversalLink(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null || config.getConfig() == null) {
            return PushMfaConstants.DEFAULT_APP_UNIVERSAL_LINK + "confirm";
        }
        String value = config.getConfig().get(PushMfaConstants.APP_UNIVERSAL_LINK_CONFIG);
        if (StringUtil.isBlank(value)) {
            return PushMfaConstants.DEFAULT_APP_UNIVERSAL_LINK + "confirm";
        }
        return value;
    }

    private record IssuedChallenge(PushChallenge challenge, String confirmToken) {}
}
