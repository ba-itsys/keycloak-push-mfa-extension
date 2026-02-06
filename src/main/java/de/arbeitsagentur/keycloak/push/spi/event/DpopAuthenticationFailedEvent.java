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
 * Event fired when DPoP authentication fails for a device API request.
 *
 * <p>This can occur due to:
 * <ul>
 *   <li>Missing or malformed access token</li>
 *   <li>Missing or malformed DPoP proof</li>
 *   <li>DPoP proof signature verification failure</li>
 *   <li>HTTP method or URI mismatch in proof</li>
 *   <li>Proof timestamp outside allowed window</li>
 *   <li>Replay attack (reused jti)</li>
 *   <li>Key thumbprint mismatch</li>
 *   <li>User/device not found</li>
 * </ul>
 *
 * @param realmId      Realm where the authentication was attempted
 * @param userId       User ID if known (may be null if not determinable)
 * @param credentialId Credential ID if known (may be null)
 * @param reason       Description of why authentication failed
 * @param httpMethod   HTTP method of the failed request
 * @param requestPath  Path of the failed request
 * @param timestamp    When this event occurred
 */
public record DpopAuthenticationFailedEvent(
        String realmId,
        String userId,
        String credentialId,
        String reason,
        String httpMethod,
        String requestPath,
        Instant timestamp)
        implements PushMfaEvent {

    @Override
    public String eventType() {
        return PushMfaEventDetails.EventTypes.DPOP_AUTHENTICATION_FAILED;
    }
}
