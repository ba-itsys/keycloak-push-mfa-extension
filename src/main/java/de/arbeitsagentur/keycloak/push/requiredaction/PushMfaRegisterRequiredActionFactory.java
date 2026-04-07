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
        appUniversalLink.setName(PushMfaConstants.ENROLLMENT_APP_UNIVERSAL_LINK_CONFIG);
        appUniversalLink.setLabel("Enrollment universal link");
        appUniversalLink.setType(ProviderConfigProperty.STRING_TYPE);
        appUniversalLink.setHelpText(
                "App link (android) or universal link (iOS) for enrollment on the same device, e.g., https://push-mfa-app.com/enroll");
        appUniversalLink.setDefaultValue(PushMfaConstants.DEFAULT_APP_UNIVERSAL_LINK + "enroll");

        ProviderConfigProperty useRequestUri = new ProviderConfigProperty();
        useRequestUri.setName(PushMfaConstants.ENROLLMENT_USE_REQUEST_URI_CONFIG);
        useRequestUri.setLabel("Use request_uri for QR and app link");
        useRequestUri.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        useRequestUri.setHelpText(
                "When enabled, the QR code and same-device app link carry a short-lived request_uri instead of the full enrollment token.");
        useRequestUri.setDefaultValue(Boolean.FALSE);

        ProviderConfigProperty requestUriTtl = new ProviderConfigProperty();
        requestUriTtl.setName(PushMfaConstants.ENROLLMENT_REQUEST_URI_TTL_CONFIG);
        requestUriTtl.setLabel("Enrollment request_uri TTL (seconds)");
        requestUriTtl.setType(ProviderConfigProperty.STRING_TYPE);
        requestUriTtl.setHelpText(
                "Optional shorter lifetime for enrollment request_uri handles. Leave empty to reuse the full enrollment challenge TTL.");

        CONFIG_PROPERTIES = List.of(challengeTtl, appUniversalLink, useRequestUri, requestUriTtl);
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
