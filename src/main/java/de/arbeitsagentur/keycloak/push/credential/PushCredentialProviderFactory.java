package de.arbeitsagentur.keycloak.push.credential;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

public class PushCredentialProviderFactory implements CredentialProviderFactory<PushCredentialProvider> {

    public static final String PROVIDER_ID = PushMfaConstants.CREDENTIAL_TYPE;

    @Override
    public PushCredentialProvider create(KeycloakSession session) {
        return new PushCredentialProvider(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
