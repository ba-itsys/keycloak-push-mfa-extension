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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

class RequiredActionHelperTest {

    @Test
    void findsMatchingAuthenticatorConfig() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        AuthenticationFlowModel flow = new AuthenticationFlowModel();
        flow.setId("flow-1");
        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setAuthenticator(PushMfaConstants.PROVIDER_ID);
        execution.setAuthenticatorConfig("config-1");
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();

        when(realm.getAuthenticationFlowsStream()).thenReturn(Stream.of(flow));
        when(realm.getAuthenticationExecutionsStream("flow-1")).thenReturn(Stream.of(execution));
        when(realm.getAuthenticatorConfigById("config-1")).thenReturn(config);

        assertSame(config, RequiredActionHelper.findAuthenticatorConfig(session, realm));
    }

    @Test
    void returnsNullWhenNoMatchingExecutionExists() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        AuthenticationFlowModel flow = new AuthenticationFlowModel();
        flow.setId("flow-1");
        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setAuthenticator("other-provider");

        when(realm.getAuthenticationFlowsStream()).thenReturn(Stream.of(flow));
        when(realm.getAuthenticationExecutionsStream("flow-1")).thenReturn(Stream.of(execution));

        assertNull(RequiredActionHelper.findAuthenticatorConfig(session, realm));
    }

    @Test
    void shouldAutoAddRequiredActionDefaultsToTrueAndReadsConfig() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        AuthenticationFlowModel flow = new AuthenticationFlowModel();
        flow.setId("flow-1");
        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setAuthenticator(PushMfaConstants.PROVIDER_ID);
        execution.setAuthenticatorConfig("config-1");
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PushMfaConstants.AUTO_ADD_REQUIRED_ACTION_CONFIG, "false"));

        when(realm.getAuthenticationFlowsStream()).thenReturn(Stream.of(flow));
        when(realm.getAuthenticationExecutionsStream("flow-1")).thenReturn(Stream.of(execution));
        when(realm.getAuthenticatorConfigById("config-1")).thenReturn(config);

        assertFalse(RequiredActionHelper.shouldAutoAddRequiredAction(session, realm));

        when(realm.getAuthenticationFlowsStream()).thenReturn(Stream.of());
        assertTrue(RequiredActionHelper.shouldAutoAddRequiredAction(session, realm));
    }
}
