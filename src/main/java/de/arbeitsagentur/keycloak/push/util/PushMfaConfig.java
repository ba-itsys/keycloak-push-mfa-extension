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

package de.arbeitsagentur.keycloak.push.util;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.provider.ProviderConfigProperty;

public record PushMfaConfig(Dpop dpop, Input input, Sse sse) {

    private static final ConfigPropertyDefinition DPOP_JTI_TTL_SECONDS = ConfigPropertyDefinition.integer(
            "dpop-jti-ttl-seconds",
            "DPoP JTI TTL (seconds)",
            "How long used DPoP jti values are remembered.",
            300,
            30,
            3600);
    private static final ConfigPropertyDefinition DPOP_JTI_MAX_LENGTH = ConfigPropertyDefinition.integer(
            "dpop-jti-max-length", "DPoP JTI max length", "Maximum allowed DPoP jti length.", 128, 16, 512);
    private static final ConfigPropertyDefinition DPOP_IAT_TOLERANCE_SECONDS = ConfigPropertyDefinition.integer(
            "dpop-iat-tolerance-seconds",
            "DPoP IAT tolerance (seconds)",
            "Allowed clock skew for DPoP proof iat.",
            120,
            30,
            600);
    private static final ConfigPropertyDefinition DPOP_REQUIRE_FOR_ENROLLMENT = ConfigPropertyDefinition.bool(
            "dpop-require-for-enrollment",
            "Require DPoP for enrollment",
            "Require DPoP authentication on enrollment completion. Set to false only for backward compatibility.",
            true);
    private static final ConfigPropertyDefinition DPOP_REQUIRE_ATH = ConfigPropertyDefinition.bool(
            "dpop-require-ath",
            "Require DPoP ath",
            "Require the DPoP proof ath claim on push MFA device-facing endpoints.",
            true);

    private static final ConfigPropertyDefinition INPUT_MAX_JWT_LENGTH = ConfigPropertyDefinition.integer(
            "input-max-jwt-length",
            "Max JWT length",
            "Maximum accepted JWT length for access tokens, proofs, and signed payloads.",
            16384,
            2048,
            131072);
    private static final ConfigPropertyDefinition INPUT_MAX_USER_ID_LENGTH = ConfigPropertyDefinition.integer(
            "input-max-user-id-length", "Max user ID length", "Maximum accepted user ID length.", 128, 32, 512);
    private static final ConfigPropertyDefinition INPUT_MAX_DEVICE_ID_LENGTH = ConfigPropertyDefinition.integer(
            "input-max-device-id-length", "Max device ID length", "Maximum accepted device ID length.", 128, 32, 512);
    private static final ConfigPropertyDefinition INPUT_MAX_DEVICE_TYPE_LENGTH = ConfigPropertyDefinition.integer(
            "input-max-device-type-length",
            "Max device type length",
            "Maximum accepted device type length.",
            64,
            16,
            256);
    private static final ConfigPropertyDefinition INPUT_MAX_DEVICE_LABEL_LENGTH = ConfigPropertyDefinition.integer(
            "input-max-device-label-length",
            "Max device label length",
            "Maximum accepted device label length.",
            128,
            32,
            1024);
    private static final ConfigPropertyDefinition INPUT_MAX_CREDENTIAL_ID_LENGTH = ConfigPropertyDefinition.integer(
            "input-max-credential-id-length",
            "Max credential ID length",
            "Maximum accepted credential ID length.",
            128,
            32,
            512);
    private static final ConfigPropertyDefinition INPUT_MAX_PUSH_PROVIDER_ID_LENGTH = ConfigPropertyDefinition.integer(
            "input-max-push-provider-id-length",
            "Max push provider ID length",
            "Maximum accepted push provider ID length.",
            2048,
            64,
            8192);
    private static final ConfigPropertyDefinition INPUT_MAX_PUSH_PROVIDER_TYPE_LENGTH =
            ConfigPropertyDefinition.integer(
                    "input-max-push-provider-type-length",
                    "Max push provider type length",
                    "Maximum accepted push provider type length.",
                    64,
                    16,
                    256);
    private static final ConfigPropertyDefinition INPUT_MAX_JWK_JSON_LENGTH = ConfigPropertyDefinition.integer(
            "input-max-jwk-json-length", "Max JWK JSON length", "Maximum accepted JWK JSON length.", 8192, 512, 65536);

    private static final ConfigPropertyDefinition SSE_MAX_CONNECTIONS = ConfigPropertyDefinition.integer(
            "sse-max-connections",
            "Max SSE connections",
            "Maximum number of concurrently registered SSE clients per node.",
            256,
            1,
            1024);
    private static final ConfigPropertyDefinition SSE_MAX_SECRET_LENGTH = ConfigPropertyDefinition.integer(
            "sse-max-secret-length", "Max SSE secret length", "Maximum accepted SSE secret length.", 128, 16, 1024);
    private static final ConfigPropertyDefinition SSE_HEARTBEAT_INTERVAL_SECONDS = ConfigPropertyDefinition.integer(
            "sse-heartbeat-interval-seconds",
            "SSE heartbeat interval (seconds)",
            "Interval for SSE keepalive comments while a challenge is pending.",
            15,
            5,
            300);
    private static final ConfigPropertyDefinition SSE_MAX_CONNECTION_LIFETIME_SECONDS =
            ConfigPropertyDefinition.integer(
                    "sse-max-connection-lifetime-seconds",
                    "SSE max connection lifetime (seconds)",
                    "Maximum time to keep one SSE connection open before rotating it.",
                    55,
                    15,
                    1800);
    private static final ConfigPropertyDefinition SSE_RECONNECT_DELAY_MILLIS = ConfigPropertyDefinition.integer(
            "sse-reconnect-delay-millis",
            "SSE reconnect delay (millis)",
            "Reconnect hint used for overload responses.",
            3000,
            250,
            30000);

    private static final List<ConfigPropertyDefinition> CONFIG_PROPERTIES = List.of(
            DPOP_JTI_TTL_SECONDS,
            DPOP_JTI_MAX_LENGTH,
            DPOP_IAT_TOLERANCE_SECONDS,
            DPOP_REQUIRE_FOR_ENROLLMENT,
            DPOP_REQUIRE_ATH,
            INPUT_MAX_JWT_LENGTH,
            INPUT_MAX_USER_ID_LENGTH,
            INPUT_MAX_DEVICE_ID_LENGTH,
            INPUT_MAX_DEVICE_TYPE_LENGTH,
            INPUT_MAX_DEVICE_LABEL_LENGTH,
            INPUT_MAX_CREDENTIAL_ID_LENGTH,
            INPUT_MAX_PUSH_PROVIDER_ID_LENGTH,
            INPUT_MAX_PUSH_PROVIDER_TYPE_LENGTH,
            INPUT_MAX_JWK_JSON_LENGTH,
            SSE_MAX_CONNECTIONS,
            SSE_MAX_SECRET_LENGTH,
            SSE_HEARTBEAT_INTERVAL_SECONDS,
            SSE_MAX_CONNECTION_LIFETIME_SECONDS,
            SSE_RECONNECT_DELAY_MILLIS);

    public record Dpop(
            int jtiTtlSeconds,
            int jtiMaxLength,
            int iatToleranceSeconds,
            boolean requireForEnrollment,
            boolean requireAth) {}

    public record Input(
            int maxJwtLength,
            int maxUserIdLength,
            int maxDeviceIdLength,
            int maxDeviceTypeLength,
            int maxDeviceLabelLength,
            int maxDeviceCredentialIdLength,
            int maxPushProviderIdLength,
            int maxPushProviderTypeLength,
            int maxJwkJsonLength) {}

    public record Sse(
            int maxConnections,
            int maxSecretLength,
            int heartbeatIntervalSeconds,
            int maxConnectionLifetimeSeconds,
            int reconnectDelayMillis) {}

    public record ConfigDocumentation(String key, String defaultValue, String range) {}

    public static List<ProviderConfigProperty> providerConfigMetadata() {
        return CONFIG_PROPERTIES.stream()
                .map(ConfigPropertyDefinition::toProviderConfigProperty)
                .toList();
    }

    public static List<ConfigDocumentation> documentation() {
        return CONFIG_PROPERTIES.stream()
                .map(ConfigPropertyDefinition::toDocumentation)
                .toList();
    }

    public static PushMfaConfig fromScope(Config.Scope config) {
        return new PushMfaConfig(
                new Dpop(
                        DPOP_JTI_TTL_SECONDS.intValue(config),
                        DPOP_JTI_MAX_LENGTH.intValue(config),
                        DPOP_IAT_TOLERANCE_SECONDS.intValue(config),
                        DPOP_REQUIRE_FOR_ENROLLMENT.booleanValue(config),
                        DPOP_REQUIRE_ATH.booleanValue(config)),
                new Input(
                        INPUT_MAX_JWT_LENGTH.intValue(config),
                        INPUT_MAX_USER_ID_LENGTH.intValue(config),
                        INPUT_MAX_DEVICE_ID_LENGTH.intValue(config),
                        INPUT_MAX_DEVICE_TYPE_LENGTH.intValue(config),
                        INPUT_MAX_DEVICE_LABEL_LENGTH.intValue(config),
                        INPUT_MAX_CREDENTIAL_ID_LENGTH.intValue(config),
                        INPUT_MAX_PUSH_PROVIDER_ID_LENGTH.intValue(config),
                        INPUT_MAX_PUSH_PROVIDER_TYPE_LENGTH.intValue(config),
                        INPUT_MAX_JWK_JSON_LENGTH.intValue(config)),
                new Sse(
                        SSE_MAX_CONNECTIONS.intValue(config),
                        SSE_MAX_SECRET_LENGTH.intValue(config),
                        SSE_HEARTBEAT_INTERVAL_SECONDS.intValue(config),
                        SSE_MAX_CONNECTION_LIFETIME_SECONDS.intValue(config),
                        SSE_RECONNECT_DELAY_MILLIS.intValue(config)));
    }

    private record ConfigPropertyDefinition(
            String key, String label, String helpText, String type, Object defaultValue, Integer min, Integer max) {

        static ConfigPropertyDefinition integer(
                String key, String label, String helpText, int defaultValue, int min, int max) {
            return new ConfigPropertyDefinition(
                    key, label, helpText, ProviderConfigProperty.INTEGER_TYPE, defaultValue, min, max);
        }

        static ConfigPropertyDefinition bool(String key, String label, String helpText, boolean defaultValue) {
            return new ConfigPropertyDefinition(
                    key, label, helpText, ProviderConfigProperty.BOOLEAN_TYPE, defaultValue, null, null);
        }

        int intValue(Config.Scope config) {
            Integer configured = config == null ? null : config.getInt(key, null);
            int raw = configured != null ? configured : (Integer) defaultValue;
            if (min != null && raw < min) {
                return min;
            }
            if (max != null && raw > max) {
                return max;
            }
            return raw;
        }

        boolean booleanValue(Config.Scope config) {
            Boolean configured = config == null ? null : config.getBoolean(key, null);
            return configured != null ? configured : (Boolean) defaultValue;
        }

        ProviderConfigProperty toProviderConfigProperty() {
            ProviderConfigProperty property = new ProviderConfigProperty();
            property.setName(key);
            property.setLabel(label);
            property.setHelpText(helpText);
            property.setType(type);
            property.setDefaultValue(defaultValue);
            return property;
        }

        ConfigDocumentation toDocumentation() {
            return new ConfigDocumentation(key, String.valueOf(defaultValue), range());
        }

        private String range() {
            if (min != null && max != null) {
                return min + "–" + max;
            }
            return "true/false";
        }
    }
}
