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
