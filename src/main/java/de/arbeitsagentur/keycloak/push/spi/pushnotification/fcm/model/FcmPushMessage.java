package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model;

public class FcmPushMessage {
    private String token;
    private Notification notification;
    private NotificationData data;

    public FcmPushMessage() {}

    public FcmPushMessage(String token, Notification notification, NotificationData data) {
        this.token = token;
        this.notification = notification;
        this.data = data;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Notification getNotification() {
        return notification;
    }

    public void setNotification(Notification notification) {
        this.notification = notification;
    }

    public NotificationData getData() {
        return data;
    }

    public void setData(NotificationData data) {
        this.data = data;
    }
}
