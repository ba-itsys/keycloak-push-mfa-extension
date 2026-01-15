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
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.token.PushConfirmTokenBuilder;
import java.net.URISyntaxException;
import org.apache.http.client.utils.URIBuilder;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.utils.StringUtil;

/** Helper for building URLs related to push challenges. */
public final class ChallengeUrlBuilder {

    private ChallengeUrlBuilder() {}

    public static String buildWatchUrl(AuthenticationFlowContext context, PushChallenge challenge) {
        if (challenge == null) return null;
        String watchSecret = challenge.getWatchSecret();
        if (StringUtil.isBlank(watchSecret)) {
            watchSecret = ChallengeNoteHelper.readWatchSecret(context.getAuthenticationSession());
        }
        if (StringUtil.isBlank(challenge.getId()) || StringUtil.isBlank(watchSecret)) return null;
        return context.getUriInfo()
                .getBaseUriBuilder()
                .path("realms")
                .path(context.getRealm().getName())
                .path("push-mfa/login/challenges")
                .path(challenge.getId())
                .path("events")
                .queryParam("secret", watchSecret)
                .build()
                .toString();
    }

    public static String buildPushUri(String appUniversalLink, String token) {
        if (StringUtil.isBlank(token)) return null;
        if (StringUtil.isBlank(appUniversalLink)) return token;
        try {
            return new URIBuilder(appUniversalLink).addParameter("token", token).toString();
        } catch (URISyntaxException e) {
            return token;
        }
    }

    public static String buildSameDeviceToken(
            AuthenticationFlowContext context,
            PushChallenge challenge,
            PushCredentialData credentialData,
            String confirmToken) {
        if (StringUtil.isBlank(confirmToken) || challenge == null) return confirmToken;
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (!AuthenticatorConfigHelper.shouldIncludeUserVerificationInSameDeviceToken(config)) {
            return confirmToken;
        }
        String userVerification = challenge.getUserVerificationValue();
        if (StringUtil.isBlank(userVerification)) return confirmToken;
        return PushConfirmTokenBuilder.build(
                context.getSession(),
                context.getRealm(),
                credentialData.getCredentialId(),
                challenge.getId(),
                challenge.getExpiresAt(),
                context.getUriInfo().getBaseUri(),
                userVerification);
    }
}
