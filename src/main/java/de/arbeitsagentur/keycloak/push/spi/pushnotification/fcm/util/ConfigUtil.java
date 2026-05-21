package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util;

public class ConfigUtil {

    private ConfigUtil() {
        // Prevent instantiation
    }

    /**
     * This method is exposed for testing purposes to allow mocking of environment variables.
     */
    public static String getEnvString(String envVar) {
        return System.getenv(envVar);
    }
}
