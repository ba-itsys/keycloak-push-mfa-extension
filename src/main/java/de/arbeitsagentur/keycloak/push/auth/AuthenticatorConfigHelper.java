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

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.time.Duration;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.utils.StringUtil;

/** Helper for reading authenticator configuration values. */
public final class AuthenticatorConfigHelper {

    private AuthenticatorConfigHelper() {}

    public static Duration parseDurationSeconds(AuthenticatorConfigModel config, String key, Duration defaultValue) {
        String value = getConfigValue(config, key);
        if (value == null) {
            return defaultValue;
        }
        try {
            long seconds = Long.parseLong(value);
            return seconds > 0 ? Duration.ofSeconds(seconds) : defaultValue;
        } catch (NumberFormatException ex) {
            return defaultValue;
        }
    }

    public static int parsePositiveInt(AuthenticatorConfigModel config, String key, int defaultValue) {
        String value = getConfigValue(config, key);
        if (value == null) {
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(value);
            return parsed > 0 ? parsed : defaultValue;
        } catch (NumberFormatException ex) {
            return defaultValue;
        }
    }

    public static boolean parseBoolean(AuthenticatorConfigModel config, String key, boolean defaultValue) {
        String value = getConfigValue(config, key);
        if (value == null) {
            return defaultValue;
        }
        return Boolean.parseBoolean(value);
    }

    public static PushChallenge.UserVerificationMode resolveUserVerificationMode(AuthenticatorConfigModel config) {
        String rawValue = getConfigValue(config, PushMfaConstants.USER_VERIFICATION_CONFIG);
        if (rawValue == null) {
            return PushChallenge.UserVerificationMode.NONE;
        }
        String normalized = rawValue.toLowerCase();
        return switch (normalized) {
            case PushMfaConstants.USER_VERIFICATION_NUMBER_MATCH, "number_match", "numbermatch" -> PushChallenge
                    .UserVerificationMode.NUMBER_MATCH;
            case PushMfaConstants.USER_VERIFICATION_PIN -> PushChallenge.UserVerificationMode.PIN;
            default -> PushChallenge.UserVerificationMode.NONE;
        };
    }

    public static int resolvePinLength(AuthenticatorConfigModel config) {
        int defaultValue = PushMfaConstants.DEFAULT_USER_VERIFICATION_PIN_LENGTH;
        String rawValue = getConfigValue(config, PushMfaConstants.USER_VERIFICATION_PIN_LENGTH_CONFIG);
        if (rawValue == null) {
            return defaultValue;
        }
        try {
            int configured = Integer.parseInt(rawValue);
            if (configured <= 0) {
                return defaultValue;
            }
            return Math.min(configured, 12);
        } catch (NumberFormatException ex) {
            return defaultValue;
        }
    }

    public static String resolveAppUniversalLink(AuthenticatorConfigModel config, String suffix) {
        String value = getConfigValue(config, PushMfaConstants.LOGIN_APP_UNIVERSAL_LINK_CONFIG);
        if (value == null) {
            value = getConfigValue(config, PushMfaConstants.APP_UNIVERSAL_LINK_CONFIG);
        }
        if (value == null) {
            return PushMfaConstants.DEFAULT_APP_UNIVERSAL_LINK + suffix;
        }
        return value;
    }

    public static boolean shouldIncludeUserVerificationInSameDeviceToken(AuthenticatorConfigModel config) {
        return parseBoolean(config, PushMfaConstants.SAME_DEVICE_INCLUDE_USER_VERIFICATION_CONFIG, false);
    }

    private static String getConfigValue(AuthenticatorConfigModel config, String key) {
        if (config == null || config.getConfig() == null) {
            return null;
        }
        String value = config.getConfig().get(key);
        if (StringUtil.isBlank(value)) {
            return null;
        }
        return value.trim();
    }
}
