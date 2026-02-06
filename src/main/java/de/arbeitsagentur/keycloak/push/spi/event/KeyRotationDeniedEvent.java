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
 * Event fired when a key rotation request is denied due to validation failure.
 *
 * <p>This can occur due to:
 * <ul>
 *   <li>Invalid new public key format</li>
 *   <li>Key contains private components</li>
 *   <li>DPoP authentication failure</li>
 *   <li>Key size exceeds maximum allowed</li>
 * </ul>
 *
 * @param realmId      Realm where the rotation was attempted
 * @param userId       User who attempted key rotation
 * @param credentialId Credential for which rotation was attempted
 * @param reason       Description of why the rotation was denied
 * @param timestamp    When this event occurred
 */
public record KeyRotationDeniedEvent(
        String realmId, String userId, String credentialId, String reason, Instant timestamp) implements PushMfaEvent {

    @Override
    public String eventType() {
        return PushMfaEventDetails.EventTypes.KEY_ROTATION_DENIED;
    }
}
