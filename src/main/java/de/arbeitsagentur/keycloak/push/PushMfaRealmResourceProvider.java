package de.arbeitsagentur.keycloak.push;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class PushMfaRealmResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public PushMfaRealmResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new PushMfaResource(session);
    }

    @Override
    public void close() {
        // no-op
    }
}
