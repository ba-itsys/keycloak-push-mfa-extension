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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.BadRequestException;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;

class PushMfaConfigTest {

    @Test
    void fromScopeHonorsConfiguredValues() {
        Config.Scope scope = mock(Config.Scope.class);
        when(scope.getInt("input-max-jwt-length", null)).thenReturn(2048);
        when(scope.getInt("dpop-jti-max-length", null)).thenReturn(40);
        when(scope.getBoolean("dpop-require-for-enrollment", null)).thenReturn(Boolean.FALSE);
        when(scope.getInt("sse-max-connections", null)).thenReturn(1);
        when(scope.getInt("sse-heartbeat-interval-seconds", null)).thenReturn(20);
        when(scope.getInt("sse-max-connection-lifetime-seconds", null)).thenReturn(120);
        when(scope.getInt("sse-reconnect-delay-millis", null)).thenReturn(1500);

        PushMfaConfig config = PushMfaConfig.fromScope(scope);

        assertEquals(2048, config.input().maxJwtLength());
        assertEquals(40, config.dpop().jtiMaxLength());
        assertEquals(false, config.dpop().requireForEnrollment());
        assertEquals(1, config.sse().maxConnections());
        assertEquals(20, config.sse().heartbeatIntervalSeconds());
        assertEquals(120, config.sse().maxConnectionLifetimeSeconds());
        assertEquals(1500, config.sse().reconnectDelayMillis());
    }

    @Test
    void configuredLimitsAreEnforcedByValidators() {
        Config.Scope scope = mock(Config.Scope.class);
        when(scope.getInt("input-max-jwt-length", null)).thenReturn(2048);
        when(scope.getInt("dpop-jti-max-length", null)).thenReturn(40);

        PushMfaConfig config = PushMfaConfig.fromScope(scope);
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
    }

    @Test
    void enrollmentDpopEnforcementDefaultsToTrue() {
        PushMfaConfig config = PushMfaConfig.fromScope(null);
        assertEquals(true, config.dpop().requireForEnrollment());
    }
}
