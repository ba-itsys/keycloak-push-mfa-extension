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

import java.util.Set;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;

/**
 * Service for dispatching Push MFA events to all registered listeners.
 *
 * <p>Events are dispatched synchronously to all listeners. Each listener is
 * wrapped in a try-catch to prevent one failing listener from affecting others
 * or the main authentication flow.
 */
public final class PushMfaEventService {

    private static final Logger LOG = Logger.getLogger(PushMfaEventService.class);

    private PushMfaEventService() {}

    /**
     * Fire an event to all registered {@link PushMfaEventListener} providers.
     *
     * @param session the Keycloak session
     * @param event   the event to fire
     */
    public static void fire(KeycloakSession session, PushMfaEvent event) {
        if (session == null || event == null) {
            return;
        }

        Set<PushMfaEventListener> listeners = session.getAllProviders(PushMfaEventListener.class);
        if (listeners == null || listeners.isEmpty()) {
            LOG.tracef("No PushMfaEventListener providers registered for event %s", event.eventType());
            return;
        }

        for (PushMfaEventListener listener : listeners) {
            try {
                listener.onEvent(event);
                dispatchToSpecificHandler(listener, event);
            } catch (Exception ex) {
                LOG.warnf(
                        ex,
                        "PushMfaEventListener %s threw exception handling %s",
                        listener.getClass().getName(),
                        event.eventType());
            }
        }
    }

    private static void dispatchToSpecificHandler(PushMfaEventListener listener, PushMfaEvent event) {
        switch (event) {
            case ChallengeCreatedEvent e -> listener.onChallengeCreated(e);
            case ChallengeAcceptedEvent e -> listener.onChallengeAccepted(e);
            case ChallengeDeniedEvent e -> listener.onChallengeDenied(e);
            case ChallengeResponseInvalidEvent e -> listener.onChallengeResponseInvalid(e);
            case EnrollmentCompletedEvent e -> listener.onEnrollmentCompleted(e);
            case KeyRotatedEvent e -> listener.onKeyRotated(e);
            case KeyRotationDeniedEvent e -> listener.onKeyRotationDenied(e);
            case DpopAuthenticationFailedEvent e -> listener.onDpopAuthenticationFailed(e);
        }
    }
}
