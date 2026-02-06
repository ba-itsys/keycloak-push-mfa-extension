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

import java.time.Instant;

/**
 * Event fired when a challenge response fails validation.
 *
 * <p>This can occur due to:
 * <ul>
 *   <li>Invalid signature on the response token</li>
 *   <li>User verification mismatch (wrong PIN or number)</li>
 *   <li>Credential ID mismatch</li>
 *   <li>Malformed response token</li>
 * </ul>
 *
 * @param realmId      Realm where the invalid response was received
 * @param userId       User associated with the challenge
 * @param challengeId  Unique identifier of the challenge
 * @param credentialId Credential ID from the challenge (may be null)
 * @param reason       Description of why the response was invalid
 * @param timestamp    When this event occurred
 */
public record ChallengeResponseInvalidEvent(
        String realmId, String userId, String challengeId, String credentialId, String reason, Instant timestamp)
        implements PushMfaEvent {

    @Override
    public String eventType() {
        return PushMfaEventDetails.EventTypes.CHALLENGE_RESPONSE_INVALID;
    }
}
