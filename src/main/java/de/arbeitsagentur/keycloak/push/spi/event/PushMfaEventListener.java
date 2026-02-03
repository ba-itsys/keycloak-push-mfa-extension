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

import org.keycloak.provider.Provider;

/**
 * SPI for reacting to Push MFA events.
 *
 * <p>Implementations should be thread-safe and non-blocking. Events are fired
 * synchronously, but implementations may choose to process them asynchronously.
 *
 * <p>All callback methods have default empty implementations, so listeners only
 * need to override the events they care about.
 */
public interface PushMfaEventListener extends Provider {

    /**
     * Called when a new authentication or enrollment challenge is created.
     *
     * @param event the challenge created event
     */
    default void onChallengeCreated(ChallengeCreatedEvent event) {}

    /**
     * Called when a challenge is accepted/approved by the user on their device.
     *
     * @param event the challenge accepted event
     */
    default void onChallengeAccepted(ChallengeAcceptedEvent event) {}

    /**
     * Called when a challenge is explicitly denied by the user on their device.
     *
     * @param event the challenge denied event
     */
    default void onChallengeDenied(ChallengeDeniedEvent event) {}

    /**
     * Called when a challenge response fails validation (bad signature, user verification mismatch, etc.).
     *
     * @param event the challenge response invalid event
     */
    default void onChallengeResponseInvalid(ChallengeResponseInvalidEvent event) {}

    /**
     * Called when device enrollment is successfully completed.
     *
     * @param event the enrollment completed event
     */
    default void onEnrollmentCompleted(EnrollmentCompletedEvent event) {}

    /**
     * Called when a device key is successfully rotated.
     *
     * @param event the key rotated event
     */
    default void onKeyRotated(KeyRotatedEvent event) {}

    /**
     * Called when a key rotation request is denied due to validation failure.
     *
     * @param event the key rotation denied event
     */
    default void onKeyRotationDenied(KeyRotationDeniedEvent event) {}

    /**
     * Called when DPoP authentication fails for a device API request.
     *
     * @param event the DPoP authentication failed event
     */
    default void onDpopAuthenticationFailed(DpopAuthenticationFailedEvent event) {}

    /**
     * Generic event handler called for all events before the specific handler.
     *
     * <p>Override this method if you want to handle all events uniformly
     * (e.g., for logging or metrics collection).
     *
     * @param event the event
     */
    default void onEvent(PushMfaEvent event) {}

    @Override
    default void close() {}
}
