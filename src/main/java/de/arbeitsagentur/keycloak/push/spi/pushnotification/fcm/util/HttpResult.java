package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util;

public class HttpResult {
    private final int statusCode;
    private final String body;

    public HttpResult(int statusCode, String body) {
        this.statusCode = statusCode;
        this.body = body;
    }

    public int statusCode() {
        return statusCode;
    }

    public String body() {
        return body;
    }
}
