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

package de.arbeitsagentur.keycloak.push.requiredaction;

import de.arbeitsagentur.keycloak.push.auth.ChallengeUrlBuilder;
import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.spi.event.ChallengeCreatedEvent;
import de.arbeitsagentur.keycloak.push.spi.event.PushMfaEventService;
import de.arbeitsagentur.keycloak.push.token.PushEnrollmentTokenBuilder;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

public class PushMfaRegisterRequiredAction implements RequiredActionProvider, CredentialRegistrator {

    private static final SecureRandom RANDOM = new SecureRandom();

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
     * Called after a new enrollment challenge has been created. Override to add custom behavior.
     *
     * @param context the required action context
     * @param challenge the created challenge
     */
    protected void onEnrollmentChallengeCreated(RequiredActionContext context, PushChallenge challenge) {}

    /**
     * Called after enrollment has been completed. Override to add custom behavior.
     *
     * @param context the required action context
     */
    protected void onEnrollmentCompleted(RequiredActionContext context) {}

    @Override
    public String getCredentialType(KeycloakSession session, AuthenticationSessionModel authSession) {
        return PushMfaConstants.CREDENTIAL_TYPE;
    }

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
        PushChallengeStore store = createChallengeStore(context.getSession());
        PushChallenge challenge = ensureWatchableChallenge(
                context, authSession, store, fetchOrCreateChallenge(context, authSession, store, false));

        String enrollmentToken = PushEnrollmentTokenBuilder.build(
                context.getSession(),
                context.getRealm(),
                context.getUser(),
                challenge,
                context.getUriInfo().getBaseUri());

        context.challenge(createForm(context.form(), context, enrollmentToken, challenge));
    }

    @Override
    public void processAction(RequiredActionContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        PushChallengeStore store = createChallengeStore(context.getSession());

        boolean checkOnly = formData.containsKey("check");

        if (formData.containsKey("refresh")) {
            cleanupChallenge(authSession, store);
            requiredActionChallenge(context);
            return;
        }

        boolean hasCredential = hasActiveCredential(context);

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

            context.challenge(createForm(
                    context.form().setError("push-mfa-registration-missing"), context, enrollmentToken, challenge));
            return;
        }

        cleanupChallenge(authSession, store);
        onEnrollmentCompleted(context);
        context.success();
    }

    /**
     * Checks if the user has an active push credential.
     * Override to customize credential checking.
     */
    protected boolean hasActiveCredential(RequiredActionContext context) {
        return !PushCredentialService.getActiveCredentials(context.getUser()).isEmpty();
    }

    @Override
    public void close() {
        // no-op
    }

    /**
     * Build the registration form.
     *
     * Overridable to customize the form before rendering.
     * @param form
     * @param context
     * @param enrollmentToken
     * @param challenge
     * @return
     */
    protected Response createForm(
            LoginFormsProvider form, RequiredActionContext context, String enrollmentToken, PushChallenge challenge) {
        form.setAttribute("pushUsername", context.getUser().getUsername());
        form.setAttribute("enrollmentToken", enrollmentToken);
        form.setAttribute("qrPayload", enrollmentToken);
        form.setAttribute(
                "pushQrUri", ChallengeUrlBuilder.buildPushUri(resolveAppUniversalLink(context), enrollmentToken));
        form.setAttribute("enrollChallengeId", challenge.getId());
        String eventsUrl = buildEnrollmentEventsUrl(context, challenge);
        if (eventsUrl != null) {
            form.setAttribute("enrollEventsUrl", eventsUrl);
        }
        return form.createForm("push-register.ftl");
    }

    /**
     * Fetches an existing challenge or creates a new one.
     * Override to customize challenge creation.
     */
    protected PushChallenge fetchOrCreateChallenge(
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
            challenge = createNewEnrollmentChallenge(context, authSession, store, challengeTtl);
        }

        return challenge;
    }

    /**
     * Creates a new enrollment challenge.
     * Override to customize challenge creation parameters.
     */
    protected PushChallenge createNewEnrollmentChallenge(
            RequiredActionContext context,
            AuthenticationSessionModel authSession,
            PushChallengeStore store,
            Duration challengeTtl) {
        byte[] nonceBytes = new byte[PushMfaConstants.NONCE_BYTES_SIZE];
        RANDOM.nextBytes(nonceBytes);
        String watchSecret = KeycloakModelUtils.generateId();
        PushChallenge challenge = store.create(
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

        PushMfaEventService.fire(
                context.getSession(),
                new ChallengeCreatedEvent(
                        challenge.getRealmId(),
                        challenge.getUserId(),
                        challenge.getId(),
                        challenge.getType(),
                        challenge.getKeycloakCredentialId(),
                        challenge.getClientId(),
                        challenge.getUserVerificationMode(),
                        challenge.getExpiresAt(),
                        Instant.now()));

        onEnrollmentChallengeCreated(context, challenge);
        return challenge;
    }

    /**
     * Cleans up an existing challenge.
     * Override to customize cleanup behavior.
     */
    protected void cleanupChallenge(AuthenticationSessionModel authSession, PushChallengeStore store) {
        String challengeId = authSession.getAuthNote(PushMfaConstants.ENROLL_CHALLENGE_NOTE);
        if (challengeId != null) {
            store.remove(challengeId);
            authSession.removeAuthNote(PushMfaConstants.ENROLL_CHALLENGE_NOTE);
        }
        authSession.removeAuthNote(PushMfaConstants.ENROLL_SSE_TOKEN_NOTE);
    }

    /**
     * Ensures the challenge has a watch secret for SSE events.
     * Override to customize watchable challenge handling.
     */
    protected PushChallenge ensureWatchableChallenge(
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

    /**
     * Builds the URL for enrollment SSE events.
     * Override to customize the events URL.
     */
    protected String buildEnrollmentEventsUrl(RequiredActionContext context, PushChallenge challenge) {
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

    /**
     * Resolves the enrollment challenge TTL from configuration.
     * Override to customize TTL resolution.
     */
    protected Duration resolveEnrollmentTtl(RequiredActionContext context) {
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

    /**
     * Resolves the app universal link from configuration.
     * Override to customize link resolution.
     */
    protected String resolveAppUniversalLink(RequiredActionContext context) {
        RequiredActionConfigModel config = context.getConfig();
        if (config == null || config.getConfig() == null) {
            return PushMfaConstants.DEFAULT_APP_UNIVERSAL_LINK + "enroll";
        }
        String value = config.getConfig().get(PushMfaConstants.ENROLLMENT_APP_UNIVERSAL_LINK_CONFIG);
        if (StringUtil.isBlank(value)) {
            value = config.getConfig().get(PushMfaConstants.APP_UNIVERSAL_LINK_CONFIG);
        }
        if (StringUtil.isBlank(value)) {
            return PushMfaConstants.DEFAULT_APP_UNIVERSAL_LINK + "enroll";
        }
        return value;
    }
}
