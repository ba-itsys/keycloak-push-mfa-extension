package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm;

public enum NotificationSendResult {
    SUCCESS("Notification sent successfully"),
    NO_CREDENTIALS("Failed to load FCM credentials"),
    TOKEN_REQUEST_FAILED("Failed to retrieve FCM token"),
    NOTIFICATION_SEND_FAILED("Failed to send notification");

    private final String message;

    NotificationSendResult(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
