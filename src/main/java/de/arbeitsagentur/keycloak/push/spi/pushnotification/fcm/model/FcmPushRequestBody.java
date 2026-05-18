package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model;

public class FcmPushRequestBody {
    private FcmPushMessage message;

    public FcmPushRequestBody() {}

    public FcmPushRequestBody(FcmPushMessage message) {
        this.message = message;
    }

    public FcmPushMessage getMessage() {
        return message;
    }

    public void setMessage(FcmPushMessage message) {
        this.message = message;
    }
}
