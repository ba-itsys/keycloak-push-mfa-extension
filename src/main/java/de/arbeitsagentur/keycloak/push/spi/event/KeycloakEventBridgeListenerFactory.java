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
import de.arbeitsagentur.keycloak.push.spi.PushMfaEventListenerFactory;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for the {@link KeycloakEventBridgeListener}.
 *
 * <p>This factory creates listeners that bridge Push MFA events to Keycloak's standard
 * event system. Events emitted through this bridge will appear in:
 * <ul>
 *   <li>Keycloak Admin Console (Events tab)</li>
 *   <li>Keycloak Event Store (database)</li>
 *   <li>Standard Keycloak EventListenerProviders</li>
 * </ul>
 *
 * <p>This listener is registered by default and works alongside other Push MFA event listeners.
 * Multiple listeners can be active simultaneously since the SPI supports multi-provider mode.
 */
public class KeycloakEventBridgeListenerFactory implements PushMfaEventListenerFactory {

    public static final String ID = "keycloak-event-bridge";

    @Override
    public PushMfaEventListener create(KeycloakSession session) {
        return new KeycloakEventBridgeListener(session);
    }

    @Override
    public void init(Config.Scope config) {
        // no configuration needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no post-initialization needed
    }

    @Override
    public void close() {
        // no resources to close
    }

    @Override
    public String getId() {
        return ID;
    }
}
