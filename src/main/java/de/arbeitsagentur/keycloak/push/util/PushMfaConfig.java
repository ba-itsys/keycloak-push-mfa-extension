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

import org.keycloak.Config;

public record PushMfaConfig(Dpop dpop, Input input, Sse sse) {

    public record Dpop(int jtiTtlSeconds, int jtiMaxLength) {}

    public record Input(
            int maxJwtLength,
            int maxUserIdLength,
            int maxDeviceIdLength,
            int maxDeviceTypeLength,
            int maxDeviceLabelLength,
            int maxCredentialIdLength,
            int maxPushProviderIdLength,
            int maxPushProviderTypeLength,
            int maxJwkJsonLength) {}

    public record Sse(int maxConnections, int maxSecretLength) {}

    public static PushMfaConfig load() {
        Config.Scope root = Config.scope("push-mfa");
        Config.Scope keycloakRoot = Config.scope("keycloak").scope("push-mfa");
        Config.Scope dpop = root.scope("dpop");
        Config.Scope keycloakDpop = keycloakRoot.scope("dpop");
        Config.Scope input = root.scope("input");
        Config.Scope keycloakInput = keycloakRoot.scope("input");
        Config.Scope sse = root.scope("sse");
        Config.Scope keycloakSse = keycloakRoot.scope("sse");

        return new PushMfaConfig(
                new Dpop(
                        boundedInt(dpop, keycloakDpop, "dpop", "jtiTtlSeconds", 300, 30, 3600),
                        boundedInt(dpop, keycloakDpop, "dpop", "jtiMaxLength", 128, 16, 512)),
                new Input(
                        boundedInt(input, keycloakInput, "input", "maxJwtLength", 16384, 2048, 131072),
                        boundedInt(input, keycloakInput, "input", "maxUserIdLength", 128, 32, 512),
                        boundedInt(input, keycloakInput, "input", "maxDeviceIdLength", 128, 32, 512),
                        boundedInt(input, keycloakInput, "input", "maxDeviceTypeLength", 64, 16, 256),
                        boundedInt(input, keycloakInput, "input", "maxDeviceLabelLength", 128, 32, 1024),
                        boundedInt(input, keycloakInput, "input", "maxCredentialIdLength", 128, 32, 512),
                        boundedInt(input, keycloakInput, "input", "maxPushProviderIdLength", 2048, 64, 8192),
                        boundedInt(input, keycloakInput, "input", "maxPushProviderTypeLength", 64, 16, 256),
                        boundedInt(input, keycloakInput, "input", "maxJwkJsonLength", 8192, 512, 65536)),
                new Sse(
                        boundedInt(sse, keycloakSse, "sse", "maxConnections", 256, 1, 1024),
                        boundedInt(sse, keycloakSse, "sse", "maxSecretLength", 128, 16, 1024)));
    }

    private static int boundedInt(
            Config.Scope config, Config.Scope fallback, String group, String key, int defaultValue, int min, int max) {
        String kebabKey = toKebabCase(key);
        Integer configured = readInt(config, key, kebabKey);
        if (configured == null) {
            configured = readInt(fallback, key, kebabKey);
        }
        if (configured == null) {
            configured = readSystemInt(
                    "keycloak.push-mfa." + group + "." + key,
                    "keycloak.push-mfa." + group + "." + kebabKey,
                    "push-mfa." + group + "." + key,
                    "push-mfa." + group + "." + kebabKey);
        }
        int raw = configured != null ? configured : defaultValue;
        if (raw < min) {
            return min;
        }
        if (raw > max) {
            return max;
        }
        return raw;
    }

    private static Integer readInt(Config.Scope scope, String key, String kebabKey) {
        if (scope == null) {
            return null;
        }
        Integer configured = scope.getInt(key, null);
        if (configured != null) {
            return configured;
        }
        if (!key.equals(kebabKey)) {
            return scope.getInt(kebabKey, null);
        }
        return null;
    }

    private static Integer readSystemInt(String... propertyNames) {
        for (String propertyName : propertyNames) {
            if (propertyName == null || propertyName.isBlank()) {
                continue;
            }
            String raw = System.getProperty(propertyName);
            if (raw == null || raw.isBlank()) {
                raw = System.getenv(toEnvVarName(propertyName));
            }
            if (raw == null || raw.isBlank()) {
                continue;
            }
            try {
                return Integer.parseInt(raw.trim());
            } catch (NumberFormatException ignored) {
                // ignore invalid config values
            }
        }
        return null;
    }

    private static String toEnvVarName(String propertyName) {
        return propertyName.toUpperCase().replace('.', '_').replace('-', '_');
    }

    private static String toKebabCase(String value) {
        if (value == null || value.isBlank()) {
            return value;
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (Character.isUpperCase(ch)) {
                if (!builder.isEmpty()) {
                    builder.append('-');
                }
                builder.append(Character.toLowerCase(ch));
            } else {
                builder.append(ch);
            }
        }
        return builder.toString();
    }
}
