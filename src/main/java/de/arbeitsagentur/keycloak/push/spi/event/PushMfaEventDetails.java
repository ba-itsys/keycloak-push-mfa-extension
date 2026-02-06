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

package de.arbeitsagentur.keycloak.push.spi.event;

/**
 * Constants for Push MFA event details in Keycloak's event system.
 *
 * <p>Use these constants when processing Push MFA events from Keycloak's standard event system
 * (Admin Console, Event Store, EventListenerProviders).
 *
 * <p>Example usage:
 * <pre>{@code
 * public void onEvent(Event event) {
 *     if (event.getType() == EventType.UPDATE_CREDENTIAL) {
 *         String eventType = event.getDetails().get(PushMfaEventDetails.EVENT_TYPE);
 *         if (PushMfaEventDetails.EventTypes.ENROLLMENT_COMPLETED.equals(eventType)) {
 *             // Handle new credential creation
 *         } else if (PushMfaEventDetails.EventTypes.KEY_ROTATED.equals(eventType)) {
 *             // Handle key rotation
 *         }
 *     }
 * }
 * }</pre>
 */
public final class PushMfaEventDetails {

    private PushMfaEventDetails() {}

    // Detail keys (used as keys in Keycloak event details map)

    /** Detail key for the Push MFA event type. Value is one of {@link EventTypes}. */
    public static final String EVENT_TYPE = "push_mfa_event_type";

    /** Detail key for the challenge ID. */
    public static final String CHALLENGE_ID = "push_mfa_challenge_id";

    /** Detail key for the challenge type (AUTHENTICATION or ENROLLMENT). */
    public static final String CHALLENGE_TYPE = "push_mfa_challenge_type";

    /** Detail key for the credential ID. */
    public static final String CREDENTIAL_ID = "push_mfa_credential_id";

    /** Detail key for the device ID. */
    public static final String DEVICE_ID = "push_mfa_device_id";

    /** Detail key for the device type (e.g., iOS, Android). */
    public static final String DEVICE_TYPE = "push_mfa_device_type";

    /** Detail key for the user verification mode. */
    public static final String USER_VERIFICATION = "push_mfa_user_verification";

    /** Detail key for error/failure reasons. */
    public static final String REASON = "push_mfa_reason";

    /** Detail key for the HTTP method (used in DPoP auth failures). */
    public static final String HTTP_METHOD = "push_mfa_http_method";

    /** Detail key for the request path (used in DPoP auth failures). */
    public static final String REQUEST_PATH = "push_mfa_request_path";

    /**
     * Event type values for the {@link #EVENT_TYPE} detail.
     *
     * <p>Use these to distinguish between different Push MFA events that may share the same
     * Keycloak EventType (e.g., both ENROLLMENT_COMPLETED and KEY_ROTATED map to UPDATE_CREDENTIAL).
     */
    public static final class EventTypes {
        private EventTypes() {}

        /** A new authentication or enrollment challenge was created. */
        public static final String CHALLENGE_CREATED = "CHALLENGE_CREATED";

        /** User approved the challenge on their device. */
        public static final String CHALLENGE_ACCEPTED = "CHALLENGE_ACCEPTED";

        /** User denied the challenge on their device. */
        public static final String CHALLENGE_DENIED = "CHALLENGE_DENIED";

        /** Challenge response validation failed. */
        public static final String CHALLENGE_RESPONSE_INVALID = "CHALLENGE_RESPONSE_INVALID";

        /** Device enrollment completed successfully (new credential created). */
        public static final String ENROLLMENT_COMPLETED = "ENROLLMENT_COMPLETED";

        /** Device key was successfully rotated. */
        public static final String KEY_ROTATED = "KEY_ROTATED";

        /** Key rotation request failed validation. */
        public static final String KEY_ROTATION_DENIED = "KEY_ROTATION_DENIED";

        /** DPoP authentication failed for device API request. */
        public static final String DPOP_AUTHENTICATION_FAILED = "DPOP_AUTHENTICATION_FAILED";
    }

    /**
     * Error codes used in Keycloak error events.
     *
     * <p>These appear in {@code Event.getError()} for error events.
     */
    public static final class ErrorCodes {
        private ErrorCodes() {}

        /** User denied the push challenge. */
        public static final String CHALLENGE_DENIED = "push_mfa_challenge_denied";

        /** Challenge response was invalid (bad signature, wrong PIN, etc.). */
        public static final String INVALID_RESPONSE = "push_mfa_invalid_response";

        /** Key rotation request was denied. */
        public static final String KEY_ROTATION_DENIED = "push_mfa_key_rotation_denied";

        /** DPoP authentication failed. */
        public static final String DPOP_AUTH_FAILED = "push_mfa_dpop_auth_failed";
    }
}
