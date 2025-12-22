package de.arbeitsagentur.keycloak.push.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import jakarta.ws.rs.BadRequestException;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PushMfaConfigTest {

    @Test
    void loadHonorsSystemProperties() {
        Map<String, String> properties = Map.of(
                "keycloak.push-mfa.input.maxJwtLength", "2048",
                "keycloak.push-mfa.dpop.jtiMaxLength", "40",
                "keycloak.push-mfa.sse.maxConnections", "1");

        withSystemProperties(properties, () -> {
            PushMfaConfig config = PushMfaConfig.load();
            assertEquals(2048, config.input().maxJwtLength());
            assertEquals(40, config.dpop().jtiMaxLength());
            assertEquals(1, config.sse().maxConnections());
        });
    }

    @Test
    void configuredLimitsAreEnforcedByValidators() {
        Map<String, String> properties = Map.of(
                "keycloak.push-mfa.input.maxJwtLength", "2048",
                "keycloak.push-mfa.dpop.jtiMaxLength", "40");

        withSystemProperties(properties, () -> {
            PushMfaConfig config = PushMfaConfig.load();
            String oversizedToken = "a".repeat(config.input().maxJwtLength() + 1);
            assertThrows(
                    BadRequestException.class,
                    () -> PushMfaInputValidator.requireMaxLength(
                            oversizedToken, config.input().maxJwtLength(), "token"));

            String oversizedJti = "a".repeat(config.dpop().jtiMaxLength() + 1);
            assertThrows(
                    BadRequestException.class,
                    () -> PushMfaInputValidator.requireMaxLength(
                            oversizedJti, config.dpop().jtiMaxLength(), "jti"));
        });
    }

    private static void withSystemProperties(Map<String, String> properties, Runnable action) {
        Map<String, String> previous = new HashMap<>();
        for (Map.Entry<String, String> entry : properties.entrySet()) {
            String key = entry.getKey();
            previous.put(key, System.getProperty(key));
            System.setProperty(key, entry.getValue());
        }
        try {
            action.run();
        } finally {
            for (Map.Entry<String, String> entry : previous.entrySet()) {
                if (entry.getValue() == null) {
                    System.clearProperty(entry.getKey());
                } else {
                    System.setProperty(entry.getKey(), entry.getValue());
                }
            }
        }
    }
}
