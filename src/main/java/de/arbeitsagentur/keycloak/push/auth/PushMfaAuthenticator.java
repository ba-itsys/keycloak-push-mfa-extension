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

import de.arbeitsagentur.keycloak.push.challenge.PendingChallengeGuard;
import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.token.PushConfirmTokenBuilder;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

public class PushMfaAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String requestChallengeId = ChallengeNoteHelper.firstNonBlank(form.getFirst("challengeId"));
        String storedChallengeId = ChallengeNoteHelper.readChallengeId(authSession);
        boolean isRefresh = form.containsKey("refresh") || form.containsKey("cancel");
        boolean looksLikePrimaryLogin = form.containsKey("username") || form.containsKey("password");

        if (!looksLikePrimaryLogin && !StringUtil.isBlank(requestChallengeId)) {
            if (StringUtil.isBlank(storedChallengeId)) {
                ChallengeNoteHelper.storeChallengeId(authSession, requestChallengeId);
            }
            action(context);
            return;
        }
        if (!looksLikePrimaryLogin && isRefresh && storedChallengeId != null) {
            action(context);
            return;
        }

        CredentialAndData cred = resolveCredential(context.getUser());
        if (cred == null) {
            context.success();
            return;
        }
        if (checkPendingChallengeLimit(context, null)) {
            return;
        }
        issueAndShowChallenge(context, cred.credential, cred.data);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        PushChallengeStore store = new PushChallengeStore(context.getSession());
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String challengeId = ChallengeNoteHelper.firstNonBlank(
                ChallengeNoteHelper.readChallengeId(authSession), form.getFirst("challengeId"));

        boolean retryRequested = form.containsKey("retry");
        boolean refreshRequested = form.containsKey("refresh");
        boolean cancelRequested = form.containsKey("cancel");

        if (challengeId == null) {
            if (retryRequested) {
                retryChallenge(context, store);
            } else {
                showError(context, "push-mfa-missing-challenge", Response.Status.INTERNAL_SERVER_ERROR);
            }
            return;
        }

        Optional<PushChallenge> challenge = store.get(challengeId);
        if (challenge.isEmpty()) {
            ChallengeNoteHelper.clear(authSession);
            if (retryRequested) {
                retryChallenge(context, store);
            } else {
                showExpiredError(context);
            }
            return;
        }

        PushChallenge current = challenge.get();
        if (!isExpectedChallenge(context, current)) {
            ChallengeNoteHelper.clear(authSession);
            if (cancelRequested) {
                context.forkWithErrorMessage(new FormMessage("push-mfa-cancelled-message"));
            } else {
                retryChallenge(context, store);
            }
            return;
        }

        if (cancelRequested) {
            store.resolve(challengeId, PushChallengeStatus.DENIED);
            store.remove(challengeId);
            ChallengeNoteHelper.clear(authSession);
            context.forkWithErrorMessage(new FormMessage("push-mfa-cancelled-message"));
            return;
        }

        if (refreshRequested && current.getStatus() == PushChallengeStatus.PENDING) {
            store.removeWithoutIndex(challengeId);
            ChallengeNoteHelper.clear(authSession);
            retryChallenge(context, store);
            return;
        }

        handleStatus(context, store, current);
    }

    private void handleStatus(AuthenticationFlowContext context, PushChallengeStore store, PushChallenge ch) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        switch (ch.getStatus()) {
            case APPROVED -> {
                store.remove(ch.getId());
                ChallengeNoteHelper.clear(authSession);
                context.success();
            }
            case DENIED -> {
                store.remove(ch.getId());
                ChallengeNoteHelper.clear(authSession);
                showDeniedError(context);
            }
            case EXPIRED -> {
                store.remove(ch.getId());
                ChallengeNoteHelper.clear(authSession);
                showExpiredError(context);
            }
            case PENDING -> showWaitingFormForExisting(context, ch);
        }
    }

    private void retryChallenge(AuthenticationFlowContext context, PushChallengeStore store) {
        if (checkPendingChallengeLimit(context, null)) {
            return;
        }
        CredentialAndData cred = resolveCredential(context.getUser());
        if (cred == null) {
            context.success();
            return;
        }
        issueAndShowChallenge(context, cred.credential, cred.data);
    }

    private void issueAndShowChallenge(
            AuthenticationFlowContext context, CredentialModel cred, PushCredentialData data) {
        PushChallengeStore store = new PushChallengeStore(context.getSession());
        Duration ttl = AuthenticatorConfigHelper.parseDurationSeconds(
                context.getAuthenticatorConfig(),
                PushMfaConstants.LOGIN_CHALLENGE_TTL_CONFIG,
                PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL);
        ClientModel client = context.getAuthenticationSession().getClient();
        String clientId = client != null ? client.getClientId() : null;
        String rootSessionId = getRootSessionId(context);

        ChallengeIssuer.IssuedChallenge issued =
                ChallengeIssuer.issue(context, store, data, cred, ttl, clientId, rootSessionId);
        showWaitingForm(context, issued.challenge(), data, issued.confirmToken());
    }

    private void showWaitingFormForExisting(AuthenticationFlowContext context, PushChallenge ch) {
        CredentialModel cred = resolveCredentialForChallenge(context.getUser(), ch);
        PushCredentialData data = cred != null ? PushCredentialService.readCredentialData(cred) : null;
        String confirmToken = (data != null && data.getCredentialId() != null)
                ? PushConfirmTokenBuilder.build(
                        context.getSession(),
                        context.getRealm(),
                        data.getCredentialId(),
                        ch.getId(),
                        ch.getExpiresAt(),
                        context.getUriInfo().getBaseUri())
                : null;
        showWaitingForm(context, ch, data, confirmToken);
    }

    private void showWaitingForm(
            AuthenticationFlowContext context, PushChallenge ch, PushCredentialData data, String token) {
        String appLink = AuthenticatorConfigHelper.resolveAppUniversalLink(context.getAuthenticatorConfig(), "confirm");
        String sameDeviceToken = ChallengeUrlBuilder.buildSameDeviceToken(context, ch, data, token);
        String sameDeviceUri = ChallengeUrlBuilder.buildPushUri(appLink, sameDeviceToken);
        context.challenge(createForm(context.form(), context, ch, data, token, appLink, sameDeviceUri));
    }

    protected Response createForm(
            LoginFormsProvider form,
            AuthenticationFlowContext context,
            PushChallenge ch,
            PushCredentialData data,
            String token,
            String appLink,
            String sameDeviceUri) {
        form.setAttribute("challengeId", ch != null ? ch.getId() : null)
                .setAttribute("pushUsername", context.getUser().getUsername())
                .setAttribute("pushConfirmToken", token)
                .setAttribute("pushCredentialId", data != null ? data.getCredentialId() : null)
                .setAttribute("pushMessageVersion", String.valueOf(PushMfaConstants.PUSH_MESSAGE_VERSION))
                .setAttribute("pushMessageType", String.valueOf(PushMfaConstants.PUSH_MESSAGE_TYPE))
                .setAttribute("appUniversalLink", appLink)
                .setAttribute("pushSameDeviceUri", sameDeviceUri);

        if (ch != null
                && ch.getUserVerificationMode() != PushChallenge.UserVerificationMode.NONE
                && !StringUtil.isBlank(ch.getUserVerificationValue())) {
            form.setAttribute(
                            "pushUserVerificationMode",
                            ch.getUserVerificationMode().name())
                    .setAttribute("pushUserVerificationValue", ch.getUserVerificationValue());
        }
        String watchUrl = ChallengeUrlBuilder.buildWatchUrl(context, ch);
        if (watchUrl != null) {
            form.setAttribute("pushChallengeWatchUrl", watchUrl);
        }
        return form.createForm("push-wait.ftl");
    }

    private boolean checkPendingChallengeLimit(AuthenticationFlowContext context, String excludeId) {
        PushChallengeStore store = new PushChallengeStore(context.getSession());
        int maxPending = AuthenticatorConfigHelper.parsePositiveInt(
                context.getAuthenticatorConfig(),
                PushMfaConstants.MAX_PENDING_AUTH_CHALLENGES_CONFIG,
                PushMfaConstants.DEFAULT_MAX_PENDING_AUTH_CHALLENGES);
        String rootSessionId = getRootSessionId(context);

        PendingChallengeGuard guard = new PendingChallengeGuard(store);
        var pending = guard.cleanAndCount(
                context.getRealm().getId(),
                context.getUser().getId(),
                rootSessionId,
                excludeId,
                ch -> isAuthSessionActive(context, ch),
                ch -> resolveCredentialForChallenge(context.getUser(), ch) != null);

        if (pending.pendingCount() >= maxPending) {
            context.failureChallenge(
                    AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR,
                    context.form()
                            .setError("push-mfa-too-many-challenges")
                            .createErrorPage(Response.Status.TOO_MANY_REQUESTS));
            return true;
        }
        return false;
    }

    private boolean isExpectedChallenge(AuthenticationFlowContext context, PushChallenge ch) {
        if (ch == null) {
            return false;
        }
        if (!context.getRealm().getId().equals(ch.getRealmId())) {
            return false;
        }
        if (!context.getUser().getId().equals(ch.getUserId())) {
            return false;
        }
        if (ch.getType() != PushChallenge.Type.AUTHENTICATION) {
            return false;
        }
        String rootSessionId = getRootSessionId(context);
        String challengeRoot = ch.getRootSessionId();
        if (!StringUtil.isBlank(challengeRoot) && !StringUtil.isBlank(rootSessionId)) {
            return challengeRoot.equals(rootSessionId);
        }
        return true;
    }

    private boolean isAuthSessionActive(AuthenticationFlowContext context, PushChallenge ch) {
        String rootSession = ch.getRootSessionId();
        if (StringUtil.isBlank(rootSession)) {
            return true;
        }
        return context.getSession()
                        .authenticationSessions()
                        .getRootAuthenticationSession(context.getRealm(), rootSession)
                != null;
    }

    private record CredentialAndData(CredentialModel credential, PushCredentialData data) {}

    private CredentialAndData resolveCredential(UserModel user) {
        List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(user);
        if (credentials.isEmpty()) {
            return null;
        }
        CredentialModel cred = credentials.get(0);
        PushCredentialData data = PushCredentialService.readCredentialData(cred);
        if (data == null || data.getCredentialId() == null) {
            return null;
        }
        return new CredentialAndData(cred, data);
    }

    private CredentialModel resolveCredentialForChallenge(UserModel user, PushChallenge ch) {
        if (ch.getCredentialId() != null) {
            CredentialModel byId = PushCredentialService.getCredentialById(user, ch.getCredentialId());
            if (byId != null) {
                return byId;
            }
        }
        List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(user);
        return credentials.isEmpty() ? null : credentials.get(0);
    }

    private String getRootSessionId(AuthenticationFlowContext context) {
        var parent = context.getAuthenticationSession().getParentSession();
        return parent != null ? parent.getId() : null;
    }

    private void showError(AuthenticationFlowContext context, String errorKey, Response.Status status) {
        context.failureChallenge(
                AuthenticationFlowError.INTERNAL_ERROR,
                context.form().setError(errorKey).createErrorPage(status));
    }

    private void showExpiredError(AuthenticationFlowContext context) {
        context.failureChallenge(
                AuthenticationFlowError.EXPIRED_CODE,
                context.form().setError("push-mfa-expired").createForm("push-expired.ftl"));
    }

    private void showDeniedError(AuthenticationFlowContext context) {
        context.failureChallenge(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                context.form().setError("push-mfa-denied").createForm("push-denied.ftl"));
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
        if (!RequiredActionHelper.shouldAutoAddRequiredAction(session, realm)) {
            return;
        }
        if (user.getRequiredActionsStream().noneMatch(PushMfaConstants.REQUIRED_ACTION_ID::equals)) {
            user.addRequiredAction(PushMfaConstants.REQUIRED_ACTION_ID);
        }
    }

    @Override
    public void close() {}
}
