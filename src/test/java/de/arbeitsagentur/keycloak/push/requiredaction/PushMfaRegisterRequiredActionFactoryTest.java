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

package de.arbeitsagentur.keycloak.push.requiredaction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;

class PushMfaRegisterRequiredActionFactoryTest {

    @Test
    void exposesExpectedMetadataAndSingleton() {
        PushMfaRegisterRequiredActionFactory factory = new PushMfaRegisterRequiredActionFactory();

        assertEquals(PushMfaConstants.REQUIRED_ACTION_ID, factory.getId());
        assertEquals("Register Push MFA device", factory.getDisplayText());
        assertSame(factory.create(mock(KeycloakSession.class)), factory.create(mock(KeycloakSession.class)));
        assertEquals(
                List.of(
                        PushMfaConstants.ENROLLMENT_CHALLENGE_TTL_CONFIG,
                        PushMfaConstants.ENROLLMENT_APP_UNIVERSAL_LINK_CONFIG),
                factory.getConfigMetadata().stream()
                        .map(property -> property.getName())
                        .toList());
    }
}
