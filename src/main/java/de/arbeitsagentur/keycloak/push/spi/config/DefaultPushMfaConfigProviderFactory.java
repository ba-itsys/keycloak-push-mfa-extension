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

package de.arbeitsagentur.keycloak.push.spi.config;

import de.arbeitsagentur.keycloak.push.spi.PushMfaConfigProvider;
import de.arbeitsagentur.keycloak.push.spi.PushMfaConfigProviderFactory;
import de.arbeitsagentur.keycloak.push.util.PushMfaConfig;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class DefaultPushMfaConfigProviderFactory implements PushMfaConfigProviderFactory {

    public static final String ID = "default";

    private static final List<ProviderConfigProperty> CONFIG_METADATA = List.of(
            property(
                    "dpop-jti-ttl-seconds",
                    "DPoP JTI TTL (seconds)",
                    "How long used DPoP jti values are remembered.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    300),
            property(
                    "dpop-jti-max-length",
                    "DPoP JTI max length",
                    "Maximum allowed DPoP jti length.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    128),
            property(
                    "dpop-iat-tolerance-seconds",
                    "DPoP IAT tolerance (seconds)",
                    "Allowed clock skew for DPoP proof iat.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    120),
            property(
                    "dpop-require-for-enrollment",
                    "Require DPoP for enrollment",
                    "Require DPoP authentication on enrollment completion. Set to false only for backward compatibility.",
                    ProviderConfigProperty.BOOLEAN_TYPE,
                    Boolean.TRUE),
            property(
                    "input-max-jwt-length",
                    "Max JWT length",
                    "Maximum accepted JWT length for access tokens, proofs, and signed payloads.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    16384),
            property(
                    "input-max-user-id-length",
                    "Max user ID length",
                    "Maximum accepted user ID length.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    128),
            property(
                    "input-max-device-id-length",
                    "Max device ID length",
                    "Maximum accepted device ID length.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    128),
            property(
                    "input-max-device-type-length",
                    "Max device type length",
                    "Maximum accepted device type length.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    64),
            property(
                    "input-max-device-label-length",
                    "Max device label length",
                    "Maximum accepted device label length.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    128),
            property(
                    "input-max-credential-id-length",
                    "Max credential ID length",
                    "Maximum accepted credential ID length.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    128),
            property(
                    "input-max-push-provider-id-length",
                    "Max push provider ID length",
                    "Maximum accepted push provider ID length.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    2048),
            property(
                    "input-max-push-provider-type-length",
                    "Max push provider type length",
                    "Maximum accepted push provider type length.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    64),
            property(
                    "input-max-jwk-json-length",
                    "Max JWK JSON length",
                    "Maximum accepted JWK JSON length.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    8192),
            property(
                    "sse-max-connections",
                    "Max SSE connections",
                    "Maximum number of concurrently registered SSE clients per node.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    256),
            property(
                    "sse-max-secret-length",
                    "Max SSE secret length",
                    "Maximum accepted SSE secret length.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    128),
            property(
                    "sse-heartbeat-interval-seconds",
                    "SSE heartbeat interval (seconds)",
                    "Interval for SSE keepalive comments while a challenge is pending.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    15),
            property(
                    "sse-max-connection-lifetime-seconds",
                    "SSE max connection lifetime (seconds)",
                    "Maximum time to keep one SSE connection open before rotating it.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    55),
            property(
                    "sse-reconnect-delay-millis",
                    "SSE reconnect delay (millis)",
                    "Reconnect hint used for overload responses.",
                    ProviderConfigProperty.INTEGER_TYPE,
                    3000));

    private volatile PushMfaConfig config = PushMfaConfig.fromScope(null);

    @Override
    public PushMfaConfigProvider create(KeycloakSession session) {
        return new DefaultPushMfaConfigProvider(config);
    }

    @Override
    public void init(Config.Scope config) {
        this.config = PushMfaConfig.fromScope(config);
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
    public String getId() {
        return ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return CONFIG_METADATA;
    }

    private static ProviderConfigProperty property(
            String name, String label, String helpText, String type, Object defaultValue) {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(name);
        property.setLabel(label);
        property.setHelpText(helpText);
        property.setType(type);
        property.setDefaultValue(defaultValue);
        return property;
    }
}
