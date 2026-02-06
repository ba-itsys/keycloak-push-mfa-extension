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
 * Event fired when a challenge is accepted/approved by the user on their device.
 *
 * @param realmId       Realm where the challenge was accepted
 * @param userId        User who accepted the challenge
 * @param challengeId   Unique identifier of the challenge
 * @param challengeType Type of challenge (AUTHENTICATION or ENROLLMENT)
 * @param credentialId  Credential ID used to accept the challenge
 * @param clientId      OAuth client ID
 * @param deviceId      Device that accepted the challenge
 * @param timestamp     When this event occurred
 */
public record ChallengeAcceptedEvent(
        String realmId,
        String userId,
        String challengeId,
        PushChallenge.Type challengeType,
        String credentialId,
        String clientId,
        String deviceId,
        Instant timestamp)
        implements PushMfaEvent {

    @Override
    public String eventType() {
        return PushMfaEventDetails.EventTypes.CHALLENGE_ACCEPTED;
    }
}
