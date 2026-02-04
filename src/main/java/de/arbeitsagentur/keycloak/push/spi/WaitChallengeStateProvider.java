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

package de.arbeitsagentur.keycloak.push.spi;

import de.arbeitsagentur.keycloak.push.challenge.WaitChallengeState;
import java.time.Duration;
import java.util.Optional;
import org.keycloak.provider.Provider;

/**
 * SPI for storing and managing wait challenge rate limiting state.
 *
 * <p>This provider tracks consecutive unapproved push challenges per user and
 * enforces exponential backoff wait times before allowing new challenges.
 */
public interface WaitChallengeStateProvider extends Provider {

    /**
     * Retrieves the current wait state for a user.
     *
     * @param realmId the realm ID
     * @param userId the user ID
     * @param resetPeriod the period after which wait state should be considered expired
     * @return the current wait state, or empty if none exists or state has expired
     */
    Optional<WaitChallengeState> get(String realmId, String userId, Duration resetPeriod);

    /**
     * Records that a new challenge was created for a user.
     *
     * <p>This increments the consecutive unapproved counter and calculates the
     * next wait time using exponential backoff.
     *
     * @param realmId the realm ID
     * @param userId the user ID
     * @param baseWait the base wait time for the first attempt
     * @param maxWait the maximum wait time cap
     * @param resetPeriod the period after which wait state expires
     */
    void recordChallengeCreated(
            String realmId, String userId, Duration baseWait, Duration maxWait, Duration resetPeriod);

    /**
     * Resets the wait state for a user when a challenge is accepted.
     *
     * @param realmId the realm ID
     * @param userId the user ID
     */
    void reset(String realmId, String userId);
}
