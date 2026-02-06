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

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import java.time.Instant;

/**
 * Event fired when a new authentication or enrollment challenge is created.
 *
 * @param realmId              Realm where the challenge was created
 * @param userId               User for whom the challenge was created
 * @param challengeId          Unique identifier of the challenge
 * @param challengeType        Type of challenge (AUTHENTICATION or ENROLLMENT)
 * @param credentialId         Credential ID (null for enrollment challenges)
 * @param clientId             OAuth client ID (null for enrollment challenges)
 * @param userVerificationMode User verification mode (NONE, NUMBER_MATCH, or PIN)
 * @param expiresAt            When the challenge expires
 * @param timestamp            When this event occurred
 */
public record ChallengeCreatedEvent(
        String realmId,
        String userId,
        String challengeId,
        PushChallenge.Type challengeType,
        String credentialId,
        String clientId,
        PushChallenge.UserVerificationMode userVerificationMode,
        Instant expiresAt,
        Instant timestamp)
        implements PushMfaEvent {

    @Override
    public String eventType() {
        return PushMfaEventDetails.EventTypes.CHALLENGE_CREATED;
    }
}
