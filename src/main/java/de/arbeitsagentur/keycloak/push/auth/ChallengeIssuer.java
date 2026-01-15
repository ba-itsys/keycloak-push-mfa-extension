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
import de.arbeitsagentur.keycloak.push.token.PushConfirmTokenBuilder;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.time.Duration;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.sessions.AuthenticationSessionModel;

/** Helper for issuing new push challenges. */
public final class ChallengeIssuer {

    private static final Logger LOG = Logger.getLogger(ChallengeIssuer.class);

    public record IssuedChallenge(PushChallenge challenge, String confirmToken) {}

    private ChallengeIssuer() {}

    public static IssuedChallenge issue(
            AuthenticationFlowContext context,
            PushChallengeStore challengeStore,
            PushCredentialData credentialData,
            CredentialModel credential,
            Duration challengeTtl,
            String clientId,
            String rootSessionId) {

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        String watchSecret = KeycloakModelUtils.generateId();

        PushChallenge.UserVerificationMode userVerificationMode =
                AuthenticatorConfigHelper.resolveUserVerificationMode(config);
        String userVerificationValue = null;
        List<String> userVerificationOptions = List.of();

        switch (userVerificationMode) {
            case NUMBER_MATCH -> {
                userVerificationOptions = UserVerificationHelper.generateNumberMatchOptions();
                userVerificationValue = UserVerificationHelper.selectNumberMatchValue(userVerificationOptions);
            }
            case PIN -> {
                int pinLength = AuthenticatorConfigHelper.resolvePinLength(config);
                userVerificationValue = UserVerificationHelper.generatePin(pinLength);
            }
            case NONE -> {}
        }

        PushChallenge pushChallenge = challengeStore.create(
                context.getRealm().getId(),
                context.getUser().getId(),
                new byte[0],
                PushChallenge.Type.AUTHENTICATION,
                challengeTtl,
                credential.getId(),
                clientId,
                watchSecret,
                rootSessionId,
                userVerificationMode,
                userVerificationValue,
                userVerificationOptions);

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
}
