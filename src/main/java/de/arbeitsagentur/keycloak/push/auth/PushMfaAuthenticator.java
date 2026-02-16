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
import de.arbeitsagentur.keycloak.push.challenge.WaitChallengeState;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.spi.WaitChallengeStateProvider;
import de.arbeitsagentur.keycloak.push.token.PushConfirmTokenBuilder;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.time.Duration;
import java.time.Instant;
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

    /**
     * Credential and its parsed data. Protected to allow subclasses to use and extend.
     */
    protected record CredentialAndData(CredentialModel credential, PushCredentialData data) {}

    /**
     * Creates a new PushChallengeStore. Override to provide a custom store implementation.
     *
     * @param session the Keycloak session
     * @return the challenge store
     */
    protected PushChallengeStore createChallengeStore(KeycloakSession session) {
        return new PushChallengeStore(session);
    }

    /**
     * Called after a new challenge has been created. Override to add custom behavior.
     *
     * @param context the authentication flow context
     * @param challenge the created challenge
     */
    protected void onChallengeCreated(AuthenticationFlowContext context, PushChallenge challenge) {}

    /**
     * Called after a challenge has been approved. Override to add custom behavior.
     *
     * @param context the authentication flow context
     * @param challenge the approved challenge
     */
    protected void onChallengeApproved(AuthenticationFlowContext context, PushChallenge challenge) {}

    /**
     * Called after a challenge has been denied. Override to add custom behavior.
     *
     * @param context the authentication flow context
     * @param challenge the denied challenge
     */
    protected void onChallengeDenied(AuthenticationFlowContext context, PushChallenge challenge) {}

    /**
     * Called after a challenge has expired. Override to add custom behavior.
     *
     * @param context the authentication flow context
     * @param challenge the expired challenge
     */
    protected void onChallengeExpired(AuthenticationFlowContext context, PushChallenge challenge) {}

    /**
     * Authenticates the user via push MFA. This method handles multiple entry points
     * depending on the authentication flow state:
     *
     * <ol>
     *   <li><b>SSE/Polling callback:</b> When the request contains a challengeId (from SSE or
     *       polling response), delegate to {@link #action} to check the challenge status.
     *       The challengeId is stored in the auth session for subsequent requests.</li>
     *
     *   <li><b>Refresh/Cancel with existing challenge:</b> When the user requests a refresh
     *       or cancel and already has an active challenge, delegate to {@link #action}
     *       to handle the refresh or cancellation.</li>
     *
     *   <li><b>No credential configured:</b> If the user has no push MFA credential,
     *       skip this authenticator and proceed with success.</li>
     *
     *   <li><b>Primary login (default):</b> After username/password authentication,
     *       issue a new push challenge and display the waiting form.</li>
     * </ol>
     *
     * @param context the authentication flow context
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String requestChallengeId = ChallengeNoteHelper.firstNonBlank(form.getFirst("challengeId"));
        String storedChallengeId = ChallengeNoteHelper.readChallengeId(authSession);
        boolean isRefresh = form.containsKey("refresh") || form.containsKey("cancel");
        boolean looksLikePrimaryLogin = form.containsKey("username") || form.containsKey("password");

        // Scenario 1: SSE/polling callback with challenge ID
        if (isChallengeCallback(looksLikePrimaryLogin, requestChallengeId)) {
            if (StringUtil.isBlank(storedChallengeId)) {
                ChallengeNoteHelper.storeChallengeId(authSession, requestChallengeId);
            }
            action(context);
            return;
        }

        // Scenario 2: Refresh/cancel request with existing challenge
        if (isRefreshWithExistingChallenge(looksLikePrimaryLogin, isRefresh, storedChallengeId)) {
            action(context);
            return;
        }

        // Scenario 3: No push credential configured - skip MFA
        CredentialAndData cred = resolveCredential(context.getUser());
        if (cred == null) {
            context.success();
            return;
        }

        // Scenario 4: Primary login - issue new challenge
        issueWithLock(context, cred);
    }

    /**
     * Determines if this request is a challenge callback from SSE/polling.
     */
    protected boolean isChallengeCallback(boolean looksLikePrimaryLogin, String requestChallengeId) {
        return !looksLikePrimaryLogin && !StringUtil.isBlank(requestChallengeId);
    }

    /**
     * Determines if this is a refresh request with an existing challenge.
     */
    protected boolean isRefreshWithExistingChallenge(
            boolean looksLikePrimaryLogin, boolean isRefresh, String storedChallengeId) {
        return !looksLikePrimaryLogin && isRefresh && storedChallengeId != null;
    }

    /**
     * Issues a new challenge with a per-user lock to prevent race conditions.
     * Override to customize the locking or challenge issuance strategy.
     */
    protected void issueWithLock(AuthenticationFlowContext context, CredentialAndData cred) {
        PushChallengeStore store = createChallengeStore(context.getSession());
        String realmId = context.getRealm().getId();
        String userId = context.getUser().getId();

        // Acquire per-user lock to prevent race conditions in concurrent challenge creation
        if (!store.tryAcquireCreationLock(realmId, userId)) {
            showTooManyChallengesError(context);
            return;
        }

        try {
            if (checkPendingChallengeLimit(context, null)) {
                return;
            }
            if (checkWaitChallengeLimit(context)) {
                return;
            }
            issueAndShowChallenge(context, cred.credential, cred.data);
        } finally {
            store.releaseCreationLock(realmId, userId);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        PushChallengeStore store = createChallengeStore(context.getSession());
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

    /**
     * Handles the challenge status and transitions the authentication flow accordingly.
     * Override to customize status handling behavior.
     */
    protected void handleStatus(AuthenticationFlowContext context, PushChallengeStore store, PushChallenge ch) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        switch (ch.getStatus()) {
            case APPROVED -> {
                store.remove(ch.getId());
                ChallengeNoteHelper.clear(authSession);
                // Reset wait state on successful approval
                resetWaitChallengeState(context);
                onChallengeApproved(context, ch);
                context.success();
            }
            case DENIED -> {
                store.remove(ch.getId());
                ChallengeNoteHelper.clear(authSession);
                onChallengeDenied(context, ch);
                showDeniedError(context);
            }
            case EXPIRED -> {
                store.remove(ch.getId());
                ChallengeNoteHelper.clear(authSession);
                onChallengeExpired(context, ch);
                showExpiredError(context);
            }
            case PENDING -> showWaitingFormForExisting(context, ch);
        }
    }

    /**
     * Retries the challenge by resolving credentials and issuing a new challenge.
     * Override to customize retry behavior.
     */
    protected void retryChallenge(AuthenticationFlowContext context, PushChallengeStore store) {
        CredentialAndData cred = resolveCredential(context.getUser());
        if (cred == null) {
            context.success();
            return;
        }
        issueWithLock(context, cred);
    }

    /**
     * Issues a new challenge and displays the waiting form.
     * Override to customize challenge creation or form display.
     */
    protected void issueAndShowChallenge(
            AuthenticationFlowContext context, CredentialModel cred, PushCredentialData data) {
        PushChallengeStore store = createChallengeStore(context.getSession());
        Duration ttl = AuthenticatorConfigHelper.parseDurationSeconds(
                context.getAuthenticatorConfig(),
                PushMfaConstants.LOGIN_CHALLENGE_TTL_CONFIG,
                PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL);
        ClientModel client = context.getAuthenticationSession().getClient();
        String clientId = client != null ? client.getClientId() : null;
        String rootSessionId = getRootSessionId(context);

        ChallengeIssuer.IssuedChallenge issued =
                ChallengeIssuer.issue(context, store, data, cred, ttl, clientId, rootSessionId);

        // Record challenge creation for wait challenge rate limiting
        recordWaitChallengeCreated(context);

        onChallengeCreated(context, issued.challenge());
        showWaitingForm(context, issued.challenge(), data, issued.confirmToken());
    }

    /**
     * Shows the waiting form for an existing challenge.
     * Override to customize form display for existing challenges.
     */
    protected void showWaitingFormForExisting(AuthenticationFlowContext context, PushChallenge ch) {
        CredentialModel cred = resolveCredentialForChallenge(context.getUser(), ch);
        PushCredentialData data = cred != null ? PushCredentialService.readCredentialData(cred) : null;
        String confirmToken = (data != null && data.getDeviceCredentialId() != null)
                ? PushConfirmTokenBuilder.build(
                        context.getSession(),
                        context.getRealm(),
                        data.getDeviceCredentialId(),
                        ch.getId(),
                        ch.getExpiresAt(),
                        context.getUriInfo().getBaseUri())
                : null;
        showWaitingForm(context, ch, data, confirmToken);
    }

    /**
     * Shows the waiting form for a challenge.
     * Override to customize form display.
     */
    protected void showWaitingForm(
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
                .setAttribute("pushCredentialId", data != null ? data.getDeviceCredentialId() : null)
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

    /**
     * Checks if the pending challenge limit has been reached.
     * Override to customize the limit policy.
     *
     * @return true if the limit is reached and the request should be blocked
     */
    protected boolean checkPendingChallengeLimit(AuthenticationFlowContext context, String excludeId) {
        PushChallengeStore store = createChallengeStore(context.getSession());
        int maxPending = AuthenticatorConfigHelper.parsePositiveInt(
                context.getAuthenticatorConfig(),
                PushMfaConstants.MAX_PENDING_AUTH_CHALLENGES_CONFIG,
                PushMfaConstants.DEFAULT_MAX_PENDING_AUTH_CHALLENGES);

        // When wait challenge rate limiting is enabled, force max pending to 1
        // to ensure rate limiting is effective
        if (AuthenticatorConfigHelper.isWaitChallengeEnabled(context.getAuthenticatorConfig())) {
            maxPending = 1;
        }

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
            showTooManyChallengesError(context);
            return true;
        }
        return false;
    }

    /**
     * Validates whether the challenge belongs to the current authentication context.
     * Override to customize challenge validation.
     */
    protected boolean isExpectedChallenge(AuthenticationFlowContext context, PushChallenge ch) {
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

    /**
     * Checks if the authentication session for a challenge is still active.
     * Override to customize session validation.
     */
    protected boolean isAuthSessionActive(AuthenticationFlowContext context, PushChallenge ch) {
        String rootSession = ch.getRootSessionId();
        if (StringUtil.isBlank(rootSession)) {
            return true;
        }
        return context.getSession()
                        .authenticationSessions()
                        .getRootAuthenticationSession(context.getRealm(), rootSession)
                != null;
    }

    /**
     * Resolves the credential to use for authentication.
     * Override to customize credential selection strategy.
     */
    protected CredentialAndData resolveCredential(UserModel user) {
        List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(user);
        if (credentials.isEmpty()) {
            return null;
        }
        CredentialModel cred = credentials.get(0);
        PushCredentialData data = PushCredentialService.readCredentialData(cred);
        if (data == null || data.getDeviceCredentialId() == null) {
            return null;
        }
        return new CredentialAndData(cred, data);
    }

    /**
     * Resolves the credential for a specific challenge.
     * Override to customize credential resolution for existing challenges.
     */
    protected CredentialModel resolveCredentialForChallenge(UserModel user, PushChallenge ch) {
        if (ch.getKeycloakCredentialId() != null) {
            CredentialModel byId = PushCredentialService.getCredentialById(user, ch.getKeycloakCredentialId());
            if (byId != null) {
                return byId;
            }
        }
        List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(user);
        return credentials.isEmpty() ? null : credentials.get(0);
    }

    /**
     * Gets the root session ID for the current authentication context.
     */
    protected String getRootSessionId(AuthenticationFlowContext context) {
        var parent = context.getAuthenticationSession().getParentSession();
        return parent != null ? parent.getId() : null;
    }

    /**
     * Shows a generic error page. Uses {@code context.challenge()} instead of
     * {@code context.failureChallenge()} to avoid triggering Keycloak's brute force protector
     * for internal/system errors that are not credential failures.
     * Override to customize error display.
     */
    protected void showError(AuthenticationFlowContext context, String errorKey, Response.Status status) {
        context.challenge(context.form().setError(errorKey).createErrorPage(status));
    }

    /**
     * Shows the too-many-challenges error page. Uses {@code context.challenge()} instead of
     * {@code context.failureChallenge()} to avoid triggering Keycloak's brute force protector
     * for non-credential errors.
     * Override to customize the too-many-challenges error display.
     */
    protected void showTooManyChallengesError(AuthenticationFlowContext context) {
        context.challenge(context.form()
                .setError("push-mfa-too-many-challenges")
                .createErrorPage(Response.Status.TOO_MANY_REQUESTS));
    }

    /**
     * Shows the expired challenge error page. Uses {@code context.challenge()} instead of
     * {@code context.failureChallenge()} to avoid triggering Keycloak's brute force protector
     * when a challenge simply times out (the user did not respond in time).
     * Override to customize the expired error display.
     */
    protected void showExpiredError(AuthenticationFlowContext context) {
        context.challenge(context.form().setError("push-mfa-expired").createForm("push-expired.ftl"));
    }

    /**
     * Shows the denied challenge error page.
     * Override to customize the denied error display.
     */
    protected void showDeniedError(AuthenticationFlowContext context) {
        context.failureChallenge(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                context.form().setError("push-mfa-denied").createForm("push-denied.ftl"));
    }

    // Wait challenge rate limiting methods

    /**
     * Checks if the wait challenge rate limit has been reached.
     * Override to customize rate limiting behavior.
     *
     * @return true if the user must wait before creating a new challenge
     */
    protected boolean checkWaitChallengeLimit(AuthenticationFlowContext context) {
        if (!AuthenticatorConfigHelper.isWaitChallengeEnabled(context.getAuthenticatorConfig())) {
            return false;
        }

        WaitChallengeStateProvider provider = getWaitChallengeStateProvider(context);
        if (provider == null) {
            return false;
        }

        Duration resetPeriod = AuthenticatorConfigHelper.getWaitChallengeResetPeriod(context.getAuthenticatorConfig());
        Optional<WaitChallengeState> state =
                provider.get(context.getRealm().getId(), context.getUser().getId(), resetPeriod);

        if (state.isPresent() && state.get().isWaiting(Instant.now())) {
            showWaitRequiredError(context, state.get().remainingWait(Instant.now()));
            return true;
        }
        return false;
    }

    /**
     * Records that a challenge was created for wait challenge rate limiting.
     * Override to customize how challenge creation is tracked.
     */
    protected void recordWaitChallengeCreated(AuthenticationFlowContext context) {
        if (!AuthenticatorConfigHelper.isWaitChallengeEnabled(context.getAuthenticatorConfig())) {
            return;
        }

        WaitChallengeStateProvider provider = getWaitChallengeStateProvider(context);
        if (provider == null) {
            return;
        }

        provider.recordChallengeCreated(
                context.getRealm().getId(),
                context.getUser().getId(),
                AuthenticatorConfigHelper.getWaitChallengeBase(context.getAuthenticatorConfig()),
                AuthenticatorConfigHelper.getWaitChallengeMax(context.getAuthenticatorConfig()),
                AuthenticatorConfigHelper.getWaitChallengeResetPeriod(context.getAuthenticatorConfig()));
    }

    /**
     * Resets the wait challenge state after successful approval.
     * Override to customize reset behavior.
     */
    protected void resetWaitChallengeState(AuthenticationFlowContext context) {
        if (!AuthenticatorConfigHelper.isWaitChallengeEnabled(context.getAuthenticatorConfig())) {
            return;
        }

        WaitChallengeStateProvider provider = getWaitChallengeStateProvider(context);
        if (provider == null) {
            return;
        }

        provider.reset(context.getRealm().getId(), context.getUser().getId());
    }

    /**
     * Gets the wait challenge state provider.
     * Override to provide a custom provider.
     */
    protected WaitChallengeStateProvider getWaitChallengeStateProvider(AuthenticationFlowContext context) {
        return context.getSession().getProvider(WaitChallengeStateProvider.class);
    }

    /**
     * Shows the wait required error page.
     * Override to customize the wait error display.
     */
    protected void showWaitRequiredError(AuthenticationFlowContext context, Duration remainingWait) {
        context.challenge(context.form()
                .setAttribute("waitSeconds", remainingWait.toSeconds())
                .setError("push-mfa-wait-required")
                .createForm("push-wait-required.ftl"));
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
