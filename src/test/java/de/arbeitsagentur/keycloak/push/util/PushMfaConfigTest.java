/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
