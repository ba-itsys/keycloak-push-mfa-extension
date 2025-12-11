package de.arbeitsagentur.keycloak.push.service;

import de.arbeitsagentur.keycloak.push.spi.PushNotificationSender;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.utils.StringUtil;

public final class PushNotificationService {

    private static final Logger LOG = Logger.getLogger(PushNotificationService.class);

    private PushNotificationService() {}

    public static void notifyDevice(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            String clientId,
            String confirmToken,
            String credentialId,
            String challengeId,
            String pushProviderType,
            String pushProviderId) {
        String providerType =
                StringUtil.isBlank(pushProviderType) ? PushMfaConstants.DEFAULT_PUSH_PROVIDER_TYPE : pushProviderType;
        PushNotificationSender sender = session.getProvider(PushNotificationSender.class, providerType);
        if (sender == null) {
            sender = session.getProvider(PushNotificationSender.class);
        }
        if (sender == null) {
            LOG.warnf("No PushNotificationSender provider available for type %s", providerType);
            return;
        }
        sender.send(session, realm, user, confirmToken, credentialId, challengeId, pushProviderId, clientId);
    }
}
