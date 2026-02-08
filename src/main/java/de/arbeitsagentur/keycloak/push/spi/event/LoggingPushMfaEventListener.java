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

import de.arbeitsagentur.keycloak.push.spi.PushMfaEventListener;
import org.jboss.logging.Logger;

/**
 * Default implementation of {@link PushMfaEventListener} that logs all events.
 *
 * <p>This listener uses INFO level for the generic event log and DEBUG level
 * for specific event details. Warning events are logged for invalid responses
 * and denied key rotations.
 */
final class LoggingPushMfaEventListener implements PushMfaEventListener {

    private static final Logger LOG = Logger.getLogger(LoggingPushMfaEventListener.class);

    @Override
    public void onEvent(PushMfaEvent event) {
        LOG.infof(
                "Push MFA Event: type=%s, realm=%s, user=%s, timestamp=%s",
                event.eventType(), event.realmId(), event.userId(), event.timestamp());
    }

    @Override
    public void onChallengeCreated(ChallengeCreatedEvent event) {
        LOG.debugf(
                "Challenge created: id=%s, type=%s, client=%s, credential=%s, verification=%s",
                event.challengeId(),
                event.challengeType(),
                event.clientId(),
                event.deviceCredentialId(),
                event.userVerificationMode());
    }

    @Override
    public void onChallengeAccepted(ChallengeAcceptedEvent event) {
        LOG.debugf(
                "Challenge accepted: id=%s, type=%s, device=%s",
                event.challengeId(), event.challengeType(), event.deviceId());
    }

    @Override
    public void onChallengeDenied(ChallengeDeniedEvent event) {
        LOG.debugf(
                "Challenge denied: id=%s, type=%s, device=%s",
                event.challengeId(), event.challengeType(), event.deviceId());
    }

    @Override
    public void onChallengeResponseInvalid(ChallengeResponseInvalidEvent event) {
        LOG.warnf(
                "Challenge response invalid: id=%s, credential=%s, reason=%s",
                event.challengeId(), event.deviceCredentialId(), event.reason());
    }

    @Override
    public void onEnrollmentCompleted(EnrollmentCompletedEvent event) {
        LOG.debugf(
                "Enrollment completed: challenge=%s, device=%s, type=%s, credential=%s",
                event.challengeId(), event.deviceId(), event.deviceType(), event.deviceCredentialId());
    }

    @Override
    public void onKeyRotated(KeyRotatedEvent event) {
        LOG.debugf("Key rotated: credential=%s, device=%s", event.deviceCredentialId(), event.deviceId());
    }

    @Override
    public void onKeyRotationDenied(KeyRotationDeniedEvent event) {
        LOG.warnf("Key rotation denied: credential=%s, reason=%s", event.deviceCredentialId(), event.reason());
    }

    @Override
    public void onDpopAuthenticationFailed(DpopAuthenticationFailedEvent event) {
        LOG.warnf(
                "DPoP authentication failed: user=%s, credential=%s, method=%s, path=%s, reason=%s",
                event.userId(), event.deviceCredentialId(), event.httpMethod(), event.requestPath(), event.reason());
    }
}
