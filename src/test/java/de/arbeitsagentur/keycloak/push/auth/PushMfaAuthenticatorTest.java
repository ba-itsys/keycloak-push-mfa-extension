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

package de.arbeitsagentur.keycloak.push.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatorConfigModel;

class PushMfaAuthenticatorTest {

    @Test
    void numberMatchOptionsAreUnique() {
        for (int i = 0; i < 25; i++) {
            List<String> options = UserVerificationHelper.generateNumberMatchOptions();

            assertEquals(3, options.size(), () -> "Expected 3 number-match options but got: " + options);
            assertEquals(3, new HashSet<>(options).size(), () -> "Expected unique options but got: " + options);
            for (String option : options) {
                assertTrue(
                        option.matches("^(0|[1-9][0-9]?)$"),
                        () -> "Expected number-match option 0-99 but got: " + option);
            }
        }
    }

    @Test
    void numberMatchSelectionIsApproximatelyUniform() {
        int samples = 150;
        int[] counts = new int[3];
        for (int attempt = 0; attempt < samples; attempt++) {
            List<String> options = UserVerificationHelper.generateNumberMatchOptions();
            String displayed = UserVerificationHelper.selectNumberMatchValue(options);
            int index = options.indexOf(displayed);
            assertTrue(index >= 0, () -> "Displayed value not found in options: " + displayed + " vs " + options);
            counts[index]++;
        }

        // Regression test for randomness:
        // The shown number should be equally likely to be in position 0, 1, or 2 of the 3-item list.
        // We create many challenges, count which position the shown number had, and then run a chi-square test.
        // Why 18.42? With 3 buckets the test has df=2; 18.42 is the 99.99th percentile (p=0.0001).
        final double chiSquareCritical = 18.42;
        double expected = samples / 3.0;
        double chiSquare = 0.0;
        for (int count : counts) {
            double diff = count - expected;
            chiSquare += (diff * diff) / expected;
        }
        assertTrue(
                chiSquare <= chiSquareCritical,
                "Expected roughly uniform distribution across indices but got counts=" + counts[0] + "," + counts[1]
                        + "," + counts[2] + " (chiSquare=" + chiSquare + ")");

        assertTrue(
                counts[0] > 0 && counts[1] > 0 && counts[2] > 0,
                () -> "All indices should appear at least once but got counts=" + counts[0] + "," + counts[1] + ","
                        + counts[2]);
    }

    @Test
    void generatePinKeepsLeadingZeros() {
        Random deterministic = new Random() {
            private int index;
            private final int[] values = {0, 1, 2, 3};

            @Override
            public int nextInt(int bound) {
                int value = values[index % values.length];
                index++;
                return value;
            }
        };

        assertEquals("0123", UserVerificationHelper.generatePin(4, deterministic));
    }

    @Test
    void resolvePinLengthUsesConfigAndBounds() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        Map<String, String> configMap = new HashMap<>();
        config.setConfig(configMap);

        configMap.put(PushMfaConstants.USER_VERIFICATION_PIN_LENGTH_CONFIG, "6");
        assertEquals(6, AuthenticatorConfigHelper.resolvePinLength(config));

        configMap.put(PushMfaConstants.USER_VERIFICATION_PIN_LENGTH_CONFIG, "0");
        assertEquals(
                PushMfaConstants.DEFAULT_USER_VERIFICATION_PIN_LENGTH,
                AuthenticatorConfigHelper.resolvePinLength(config));

        configMap.put(PushMfaConstants.USER_VERIFICATION_PIN_LENGTH_CONFIG, "18");
        assertEquals(12, AuthenticatorConfigHelper.resolvePinLength(config));

        configMap.put(PushMfaConstants.USER_VERIFICATION_PIN_LENGTH_CONFIG, "not-a-number");
        assertEquals(
                PushMfaConstants.DEFAULT_USER_VERIFICATION_PIN_LENGTH,
                AuthenticatorConfigHelper.resolvePinLength(config));
    }
}
