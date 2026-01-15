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

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/** Helper for required action auto-add logic. */
public final class RequiredActionHelper {

    private RequiredActionHelper() {}

    public static boolean shouldAutoAddRequiredAction(KeycloakSession session, RealmModel realm) {
        AuthenticatorConfigModel config = findAuthenticatorConfig(session, realm);
        return AuthenticatorConfigHelper.parseBoolean(config, PushMfaConstants.AUTO_ADD_REQUIRED_ACTION_CONFIG, true);
    }

    public static AuthenticatorConfigModel findAuthenticatorConfig(KeycloakSession session, RealmModel realm) {
        for (AuthenticationFlowModel flow : realm.getAuthenticationFlowsStream().toList()) {
            for (AuthenticationExecutionModel exec :
                    realm.getAuthenticationExecutionsStream(flow.getId()).toList()) {
                if (PushMfaConstants.PROVIDER_ID.equals(exec.getAuthenticator())
                        && exec.getAuthenticatorConfig() != null) {
                    return realm.getAuthenticatorConfigById(exec.getAuthenticatorConfig());
                }
            }
        }
        return null;
    }
}
