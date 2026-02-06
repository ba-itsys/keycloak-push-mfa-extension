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
 * Event fired when device enrollment is successfully completed.
 *
 * @param realmId      Realm where enrollment completed
 * @param userId       User who completed enrollment
 * @param challengeId  Enrollment challenge ID that was completed
 * @param credentialId Newly created credential ID
 * @param deviceId     Device identifier
 * @param deviceType   Type/OS of the device (e.g., "iOS", "Android")
 * @param timestamp    When this event occurred
 */
public record EnrollmentCompletedEvent(
        String realmId,
        String userId,
        String challengeId,
        String credentialId,
        String deviceId,
        String deviceType,
        Instant timestamp)
        implements PushMfaEvent {

    @Override
    public String eventType() {
        return PushMfaEventDetails.EventTypes.ENROLLMENT_COMPLETED;
    }
}
