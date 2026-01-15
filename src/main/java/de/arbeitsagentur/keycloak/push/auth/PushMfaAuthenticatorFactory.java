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
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class PushMfaAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = PushMfaConstants.PROVIDER_ID;

    private static final PushMfaAuthenticator SINGLETON = new PushMfaAuthenticator();
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.ALTERNATIVE,
        AuthenticationExecutionModel.Requirement.DISABLED
    };
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        ProviderConfigProperty loginTtl = new ProviderConfigProperty();
        loginTtl.setName(PushMfaConstants.LOGIN_CHALLENGE_TTL_CONFIG);
        loginTtl.setLabel("Login challenge TTL (seconds)");
        loginTtl.setType(ProviderConfigProperty.STRING_TYPE);
        loginTtl.setHelpText("Time-to-live for login push challenges in seconds.");
        loginTtl.setDefaultValue(String.valueOf(PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.toSeconds()));

        ProviderConfigProperty maxPending = new ProviderConfigProperty();
        maxPending.setName(PushMfaConstants.MAX_PENDING_AUTH_CHALLENGES_CONFIG);
        maxPending.setLabel("Max pending login challenges");
        maxPending.setType(ProviderConfigProperty.STRING_TYPE);
        maxPending.setHelpText("Maximum number of open login challenges per user.");
        maxPending.setDefaultValue(String.valueOf(PushMfaConstants.DEFAULT_MAX_PENDING_AUTH_CHALLENGES));

        ProviderConfigProperty userVerification = new ProviderConfigProperty();
        userVerification.setName(PushMfaConstants.USER_VERIFICATION_CONFIG);
        userVerification.setLabel("User verification");
        userVerification.setType(ProviderConfigProperty.STRING_TYPE);
        userVerification.setHelpText(
                "Optional additional user verification for login approvals: none, number-match, pin.");
        userVerification.setDefaultValue(PushMfaConstants.USER_VERIFICATION_NONE);

        ProviderConfigProperty userVerificationPinLength = new ProviderConfigProperty();
        userVerificationPinLength.setName(PushMfaConstants.USER_VERIFICATION_PIN_LENGTH_CONFIG);
        userVerificationPinLength.setLabel("User verification PIN length");
        userVerificationPinLength.setType(ProviderConfigProperty.STRING_TYPE);
        userVerificationPinLength.setHelpText("Length of the PIN shown to the user when userVerification=pin.");
        userVerificationPinLength.setDefaultValue(
                String.valueOf(PushMfaConstants.DEFAULT_USER_VERIFICATION_PIN_LENGTH));

        ProviderConfigProperty sameDeviceUserVerification = new ProviderConfigProperty();
        sameDeviceUserVerification.setName(PushMfaConstants.SAME_DEVICE_INCLUDE_USER_VERIFICATION_CONFIG);
        sameDeviceUserVerification.setLabel("Same-device link includes user verification");
        sameDeviceUserVerification.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        sameDeviceUserVerification.setHelpText(
                "Include the current user verification answer in the same-device link token so the app can auto-fill it.");
        sameDeviceUserVerification.setDefaultValue(Boolean.FALSE);

        ProviderConfigProperty appUniversalLink = new ProviderConfigProperty();
        appUniversalLink.setName(PushMfaConstants.LOGIN_APP_UNIVERSAL_LINK_CONFIG);
        appUniversalLink.setLabel("Same-device login universal link");
        appUniversalLink.setType(ProviderConfigProperty.STRING_TYPE);
        appUniversalLink.setHelpText(
                "App link (android) or universal link (iOS) for same-device login, e.g., https://push-mfa-app.com/confirm");
        appUniversalLink.setDefaultValue(PushMfaConstants.DEFAULT_APP_UNIVERSAL_LINK + "confirm");

        ProviderConfigProperty autoAddRequiredAction = new ProviderConfigProperty();
        autoAddRequiredAction.setName(PushMfaConstants.AUTO_ADD_REQUIRED_ACTION_CONFIG);
        autoAddRequiredAction.setLabel("Auto-add required action");
        autoAddRequiredAction.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        autoAddRequiredAction.setHelpText(
                "Automatically add the push-mfa-register required action when user has no credential. "
                        + "Disable to allow users to add credentials via account console.");
        autoAddRequiredAction.setDefaultValue(Boolean.TRUE);

        CONFIG_PROPERTIES = List.of(
                loginTtl,
                maxPending,
                userVerification,
                userVerificationPinLength,
                sameDeviceUserVerification,
                appUniversalLink,
                autoAddRequiredAction);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Push MFA Challenge";
    }

    @Override
    public String getReferenceCategory() {
        return PushMfaConstants.CREDENTIAL_TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
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
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    public String getHelpText() {
        return "Sends a simulated push notification that must be approved in order to finish authentication.";
    }
}
