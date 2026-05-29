package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm;

import de.arbeitsagentur.keycloak.push.spi.PushNotificationSender;
import de.arbeitsagentur.keycloak.push.spi.PushNotificationSenderFactory;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class FcmPushNotificationSenderFactory implements PushNotificationSenderFactory {

    private static final String ID = "fcm";
    private String fcmUrl;

    @Override
    public PushNotificationSender create(KeycloakSession session) {
        return new FcmPushNotificationSender(fcmUrl);
    }

    @Override
    public void init(Config.Scope config) {
        fcmUrl = config.get("googleFcmUrl");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // post-init not needed
    }

    @Override
    public void close() {
        // close not needed
    }

    @Override
    public String getId() {
        return ID;
    }
}
