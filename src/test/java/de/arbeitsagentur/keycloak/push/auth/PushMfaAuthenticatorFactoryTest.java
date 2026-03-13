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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticationExecutionModel;

class PushMfaAuthenticatorFactoryTest {

    @Test
    void exposesExpectedMetadataAndSingleton() {
        PushMfaAuthenticatorFactory factory = new PushMfaAuthenticatorFactory();

        assertEquals(PushMfaConstants.PROVIDER_ID, factory.getId());
        assertEquals("Push MFA Challenge", factory.getDisplayType());
        assertEquals(PushMfaConstants.CREDENTIAL_TYPE, factory.getReferenceCategory());
        assertTrue(factory.isConfigurable());
        assertTrue(factory.isUserSetupAllowed());
        assertEquals(
                "Sends a simulated push notification that must be approved in order to finish authentication.",
                factory.getHelpText());
        assertSame(factory.create(null), factory.create(null));
        assertArrayEquals(
                new AuthenticationExecutionModel.Requirement[] {
                    AuthenticationExecutionModel.Requirement.REQUIRED,
                    AuthenticationExecutionModel.Requirement.ALTERNATIVE,
                    AuthenticationExecutionModel.Requirement.DISABLED
                },
                factory.getRequirementChoices());
    }

    @Test
    void exposesExpectedConfigProperties() {
        PushMfaAuthenticatorFactory factory = new PushMfaAuthenticatorFactory();

        List<String> propertyNames = factory.getConfigProperties().stream()
                .map(property -> property.getName())
                .toList();

        assertEquals(
                List.of(
                        PushMfaConstants.LOGIN_CHALLENGE_TTL_CONFIG,
                        PushMfaConstants.MAX_PENDING_AUTH_CHALLENGES_CONFIG,
                        PushMfaConstants.USER_VERIFICATION_CONFIG,
                        PushMfaConstants.USER_VERIFICATION_PIN_LENGTH_CONFIG,
                        PushMfaConstants.SAME_DEVICE_INCLUDE_USER_VERIFICATION_CONFIG,
                        PushMfaConstants.LOGIN_APP_UNIVERSAL_LINK_CONFIG,
                        PushMfaConstants.AUTO_ADD_REQUIRED_ACTION_CONFIG,
                        PushMfaConstants.WAIT_CHALLENGE_ENABLED_CONFIG,
                        PushMfaConstants.WAIT_CHALLENGE_BASE_SECONDS_CONFIG,
                        PushMfaConstants.WAIT_CHALLENGE_MAX_SECONDS_CONFIG,
                        PushMfaConstants.WAIT_CHALLENGE_RESET_HOURS_CONFIG),
                propertyNames);
    }
}
