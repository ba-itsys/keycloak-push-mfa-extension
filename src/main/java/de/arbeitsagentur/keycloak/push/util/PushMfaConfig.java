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

    public static PushMfaConfig fromScope(Config.Scope config) {
        return new PushMfaConfig(
                new Dpop(
                        boundedInt(config, "dpop-jti-ttl-seconds", 300, 30, 3600),
                        boundedInt(config, "dpop-jti-max-length", 128, 16, 512),
                        boundedInt(config, "dpop-iat-tolerance-seconds", 120, 30, 600),
                        bool(config, "dpop-require-for-enrollment", true),
                        bool(config, "dpop-require-ath", true)),
                new Input(
                        boundedInt(config, "input-max-jwt-length", 16384, 2048, 131072),
                        boundedInt(config, "input-max-user-id-length", 128, 32, 512),
                        boundedInt(config, "input-max-device-id-length", 128, 32, 512),
                        boundedInt(config, "input-max-device-type-length", 64, 16, 256),
                        boundedInt(config, "input-max-device-label-length", 128, 32, 1024),
                        boundedInt(config, "input-max-credential-id-length", 128, 32, 512),
                        boundedInt(config, "input-max-push-provider-id-length", 2048, 64, 8192),
                        boundedInt(config, "input-max-push-provider-type-length", 64, 16, 256),
                        boundedInt(config, "input-max-jwk-json-length", 8192, 512, 65536)),
                new Sse(
                        boundedInt(config, "sse-max-connections", 256, 1, 1024),
                        boundedInt(config, "sse-max-secret-length", 128, 16, 1024),
                        boundedInt(config, "sse-heartbeat-interval-seconds", 15, 5, 300),
                        boundedInt(config, "sse-max-connection-lifetime-seconds", 55, 15, 1800),
                        boundedInt(config, "sse-reconnect-delay-millis", 3000, 250, 30000)));
    }

    private static int boundedInt(Config.Scope config, String key, int defaultValue, int min, int max) {
        Integer configured = config == null ? null : config.getInt(key, null);
        int raw = configured != null ? configured : defaultValue;
        if (raw < min) {
            return min;
        }
        if (raw > max) {
            return max;
        }
        return raw;
    }

    private static boolean bool(Config.Scope config, String key, boolean defaultValue) {
        Boolean configured = config == null ? null : config.getBoolean(key, null);
        return configured != null ? configured : defaultValue;
    }
}
