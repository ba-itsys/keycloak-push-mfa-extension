package de.arbeitsagentur.keycloak.push.credential;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class PushCredentialProvider implements CredentialProvider<CredentialModel> {

    private final KeycloakSession session;

    public PushCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getType() {
        return PushMfaConstants.CREDENTIAL_TYPE;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, CredentialModel credentialModel) {
        if (credentialModel.getType() == null) {
            credentialModel.setType(PushMfaConstants.CREDENTIAL_TYPE);
        }
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }
        return user.credentialManager().createStoredCredential(credentialModel);
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return user.credentialManager().removeStoredCredentialById(credentialId);
    }

    @Override
    public CredentialModel getCredentialFromModel(CredentialModel model) {
        return model;
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext context) {
        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName(PushMfaConstants.USER_CREDENTIAL_DISPLAY_NAME_KEY)
                .helpText("Approve sign-ins with your registered device.")
                .iconCssClass(CredentialTypeMetadata.DEFAULT_ICON_CSS_CLASS)
                .createAction(PushMfaConstants.REQUIRED_ACTION_ID)
                .removeable(true)
                .build(session);
    }
}
