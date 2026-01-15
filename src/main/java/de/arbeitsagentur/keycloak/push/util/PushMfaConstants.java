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

import java.time.Duration;

public final class PushMfaConstants {

    private PushMfaConstants() {}

    public static final String CREDENTIAL_TYPE = "push-mfa";
    public static final String PROVIDER_ID = "push-mfa-authenticator";
    public static final String USER_CREDENTIAL_DISPLAY_NAME = "Push MFA Device";
    public static final String USER_CREDENTIAL_DISPLAY_NAME_KEY = "push-mfa-display-name";
    public static final String DEFAULT_PUSH_PROVIDER_TYPE = "log";

    public static final String CHALLENGE_NOTE = "push-mfa-challenge-id";
    public static final String CHALLENGE_WATCH_SECRET_NOTE = "push-mfa-challenge-watch-secret";
    public static final String CHALLENGE_APPROVE = "approve";
    public static final String CHALLENGE_DENY = "deny";
    public static final String ENROLL_CHALLENGE_NOTE = "push-mfa-enroll-challenge-id";
    public static final String ENROLL_SSE_TOKEN_NOTE = "push-mfa-enroll-sse-token";
    public static final String LOGIN_CHALLENGE_TTL_CONFIG = "loginChallengeTtlSeconds";
    public static final String ENROLLMENT_CHALLENGE_TTL_CONFIG = "enrollmentChallengeTtlSeconds";
    public static final String MAX_PENDING_AUTH_CHALLENGES_CONFIG = "maxPendingChallenges";
    public static final String USER_VERIFICATION_CONFIG = "userVerification";
    public static final String USER_VERIFICATION_PIN_LENGTH_CONFIG = "userVerificationPinLength";
    public static final String SAME_DEVICE_INCLUDE_USER_VERIFICATION_CONFIG = "sameDeviceIncludeUserVerification";
    public static final String LOGIN_APP_UNIVERSAL_LINK_CONFIG = "loginAppUniversalLink";
    public static final String ENROLLMENT_APP_UNIVERSAL_LINK_CONFIG = "enrollmentAppUniversalLink";
    public static final String AUTO_ADD_REQUIRED_ACTION_CONFIG = "autoAddRequiredAction";
    public static final String USER_VERIFICATION_NONE = "none";
    public static final String USER_VERIFICATION_NUMBER_MATCH = "number-match";
    public static final String USER_VERIFICATION_PIN = "pin";
    public static final int PUSH_MESSAGE_VERSION = 1;
    public static final int PUSH_MESSAGE_TYPE = 1;
    public static final String APP_UNIVERSAL_LINK_CONFIG = "appUniversalLink";
    public static final String DEFAULT_APP_UNIVERSAL_LINK = "my-secure://";

    public static final int NONCE_BYTES_SIZE = 32;
    public static final Duration DEFAULT_LOGIN_CHALLENGE_TTL = Duration.ofSeconds(120);
    public static final Duration DEFAULT_ENROLLMENT_CHALLENGE_TTL = Duration.ofSeconds(120);
    public static final int DEFAULT_MAX_PENDING_AUTH_CHALLENGES = 1;
    public static final int DEFAULT_USER_VERIFICATION_PIN_LENGTH = 4;

    public static final String REQUIRED_ACTION_ID = "push-mfa-register";
}
