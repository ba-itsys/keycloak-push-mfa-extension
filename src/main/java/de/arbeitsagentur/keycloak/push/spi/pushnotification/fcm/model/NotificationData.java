package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model;

public class NotificationData {
    private String token;

    public NotificationData() {}

    public NotificationData(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
