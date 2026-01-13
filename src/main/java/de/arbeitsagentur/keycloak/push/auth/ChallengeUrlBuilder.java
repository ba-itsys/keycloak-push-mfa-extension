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
