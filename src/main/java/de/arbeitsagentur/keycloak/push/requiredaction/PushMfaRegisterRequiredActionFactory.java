package de.arbeitsagentur.keycloak.push.requiredaction;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class PushMfaRegisterRequiredActionFactory implements RequiredActionFactory {

    private static final PushMfaRegisterRequiredAction SINGLETON = new PushMfaRegisterRequiredAction();
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        ProviderConfigProperty challengeTtl = new ProviderConfigProperty();
        challengeTtl.setName(PushMfaConstants.ENROLLMENT_CHALLENGE_TTL_CONFIG);
        challengeTtl.setLabel("Enrollment challenge TTL (seconds)");
        challengeTtl.setType(ProviderConfigProperty.STRING_TYPE);
        challengeTtl.setHelpText("Time-to-live for enrollment token and challenge checks in seconds.");
        challengeTtl.setDefaultValue(String.valueOf(PushMfaConstants.DEFAULT_ENROLLMENT_CHALLENGE_TTL.toSeconds()));

        ProviderConfigProperty appUniversalLink = new ProviderConfigProperty();
        appUniversalLink.setName(PushMfaConstants.APP_UNIVERSAL_LINK_CONFIG);
        appUniversalLink.setLabel("Companion app/universal link");
        appUniversalLink.setType(ProviderConfigProperty.STRING_TYPE);
        appUniversalLink.setHelpText("App link (android) or universal link (iOS) to launch companion app on the same device, e.g., https://push-mfa-app.com/");
        appUniversalLink.setDefaultValue(PushMfaConstants.DEFAULT_APP_UNIVERSAL_LINK + "enroll");

        CONFIG_PROPERTIES = List.of(challengeTtl, appUniversalLink);
    }

    @Override
    public String getId() {
        return PushMfaConstants.REQUIRED_ACTION_ID;
    }

    @Override
    public String getDisplayText() {
        return "Register Push MFA device";
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // no-op
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return CONFIG_PROPERTIES;
    }
}
