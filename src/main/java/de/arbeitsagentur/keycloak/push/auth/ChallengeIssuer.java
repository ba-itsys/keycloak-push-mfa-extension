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

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.service.PushNotificationService;
import de.arbeitsagentur.keycloak.push.spi.event.ChallengeCreatedEvent;
import de.arbeitsagentur.keycloak.push.spi.event.PushMfaEventService;
import de.arbeitsagentur.keycloak.push.token.PushConfirmTokenBuilder;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Helper for issuing new push challenges.
 *
 * <p><strong>Nonce handling:</strong> Authentication challenges intentionally use an empty nonce.
 * Unlike enrollment challenges (which must verify that the response came from a device that
 * received the original token), authentication challenges rely on the unguessable challenge ID
 * ({@code cid}) for security. The mobile app proves possession of the user's private key via
 * DPoP authentication, and the challenge ID binds the approval to the specific login attempt.
 * Adding a nonce would provide no additional security benefit for the authentication flow.
 *
 * <p>This class can be extended to customize challenge issuance behavior. Create a subclass
 * and override the instance methods, then use the instance-based {@link #issueChallenge} method
 * instead of the static {@link #issue} convenience method.
 */
public class ChallengeIssuer {

    private static final Logger LOG = Logger.getLogger(ChallengeIssuer.class);
    private static final ChallengeIssuer DEFAULT_INSTANCE = new ChallengeIssuer();

    /**
     * Result of issuing a challenge, containing the challenge and its confirmation token.
     */
    public record IssuedChallenge(PushChallenge challenge, String confirmToken) {}

    /**
     * Creates a new ChallengeIssuer instance.
     * Subclasses can override methods to customize behavior.
     */
    public ChallengeIssuer() {}

    /**
     * Static convenience method for issuing a challenge using the default instance.
     * For customization, create a subclass and use {@link #issueChallenge} instead.
     */
    public static IssuedChallenge issue(
            AuthenticationFlowContext context,
            PushChallengeStore challengeStore,
            PushCredentialData credentialData,
            CredentialModel credential,
            Duration challengeTtl,
            String clientId,
            String rootSessionId) {
        return DEFAULT_INSTANCE.issueChallenge(
                context, challengeStore, credentialData, credential, challengeTtl, clientId, rootSessionId);
    }

    /**
     * Issues a new push challenge. This is the main entry point for subclasses.
     * Override individual protected methods to customize specific aspects.
     */
    public IssuedChallenge issueChallenge(
            AuthenticationFlowContext context,
            PushChallengeStore challengeStore,
            PushCredentialData credentialData,
            CredentialModel credential,
            Duration challengeTtl,
            String clientId,
            String rootSessionId) {

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        String watchSecret = generateWatchSecret();

        UserVerificationResult uvResult = resolveUserVerification(config);

        PushChallenge pushChallenge = createChallenge(
                context, challengeStore, credential, challengeTtl, clientId, rootSessionId, watchSecret, uvResult);

        fireChallengeCreatedEvent(context, pushChallenge, credentialData);
        storeChallengeInSession(context, pushChallenge, watchSecret);

        String confirmToken = buildConfirmToken(context, credentialData, pushChallenge);

        logChallengeCreation(credentialData);
        sendPushNotification(context, credentialData, clientId, confirmToken, pushChallenge);

        return new IssuedChallenge(pushChallenge, confirmToken);
    }

    /**
     * Result of user verification resolution.
     */
    protected record UserVerificationResult(
            PushChallenge.UserVerificationMode mode, String value, List<String> options) {}

    /**
     * Generates a watch secret for SSE/polling.
     * Override to customize secret generation.
     */
    protected String generateWatchSecret() {
        return KeycloakModelUtils.generateId();
    }

    /**
     * Resolves user verification mode and generates verification values.
     * Override to customize user verification behavior.
     */
    protected UserVerificationResult resolveUserVerification(AuthenticatorConfigModel config) {
        PushChallenge.UserVerificationMode mode = AuthenticatorConfigHelper.resolveUserVerificationMode(config);
        String value = null;
        List<String> options = List.of();

        switch (mode) {
            case NUMBER_MATCH -> {
                options = UserVerificationHelper.generateNumberMatchOptions();
                value = UserVerificationHelper.selectNumberMatchValue(options);
            }
            case PIN -> {
                int pinLength = AuthenticatorConfigHelper.resolvePinLength(config);
                value = UserVerificationHelper.generatePin(pinLength);
            }
            case NONE -> {}
        }

        return new UserVerificationResult(mode, value, options);
    }

    /**
     * Creates the challenge in the store.
     * Override to customize challenge creation.
     */
    protected PushChallenge createChallenge(
            AuthenticationFlowContext context,
            PushChallengeStore challengeStore,
            CredentialModel credential,
            Duration challengeTtl,
            String clientId,
            String rootSessionId,
            String watchSecret,
            UserVerificationResult uvResult) {
        // Authentication challenges use an empty nonce - see class Javadoc for rationale
        return challengeStore.create(
                context.getRealm().getId(),
                context.getUser().getId(),
                new byte[0],
                PushChallenge.Type.AUTHENTICATION,
                challengeTtl,
                credential.getId(),
                clientId,
                watchSecret,
                rootSessionId,
                uvResult.mode(),
                uvResult.value(),
                uvResult.options());
    }

    /**
     * Fires the challenge created event.
     * Override to customize event firing or add additional events.
     */
    protected void fireChallengeCreatedEvent(
            AuthenticationFlowContext context, PushChallenge pushChallenge, PushCredentialData credentialData) {
        PushMfaEventService.fire(
                context.getSession(),
                new ChallengeCreatedEvent(
                        pushChallenge.getRealmId(),
                        pushChallenge.getUserId(),
                        pushChallenge.getId(),
                        pushChallenge.getType(),
                        credentialData.getCredentialId(),
                        pushChallenge.getClientId(),
                        pushChallenge.getUserVerificationMode(),
                        pushChallenge.getExpiresAt(),
                        Instant.now()));
    }

    /**
     * Stores the challenge information in the authentication session.
     * Override to customize session storage.
     */
    protected void storeChallengeInSession(
            AuthenticationFlowContext context, PushChallenge pushChallenge, String watchSecret) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        ChallengeNoteHelper.storeChallengeId(authSession, pushChallenge.getId());
        ChallengeNoteHelper.storeWatchSecret(authSession, watchSecret);
    }

    /**
     * Builds the confirmation token for the challenge.
     * Override to customize token generation.
     */
    protected String buildConfirmToken(
            AuthenticationFlowContext context, PushCredentialData credentialData, PushChallenge pushChallenge) {
        return PushConfirmTokenBuilder.build(
                context.getSession(),
                context.getRealm(),
                credentialData.getCredentialId(),
                pushChallenge.getId(),
                pushChallenge.getExpiresAt(),
                context.getUriInfo().getBaseUri());
    }

    /**
     * Logs the challenge creation.
     * Override to customize logging.
     */
    protected void logChallengeCreation(PushCredentialData credentialData) {
        LOG.debugf(
                "Push message prepared {version=%d,type=%d,credentialId=%s}",
                PushMfaConstants.PUSH_MESSAGE_VERSION,
                PushMfaConstants.PUSH_MESSAGE_TYPE,
                credentialData.getCredentialId());
    }

    /**
     * Sends the push notification to the device.
     * Override to customize notification delivery.
     */
    protected void sendPushNotification(
            AuthenticationFlowContext context,
            PushCredentialData credentialData,
            String clientId,
            String confirmToken,
            PushChallenge pushChallenge) {
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
    }
}
