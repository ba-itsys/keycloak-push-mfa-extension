package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model;

public class Notification {
    private String title;
    private String body;

    // Constructors
    public Notification() {}

    public Notification(String title, String body) {
        this.title = title;
        this.body = body;
    }

    // Getters and Setters
    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }
}
