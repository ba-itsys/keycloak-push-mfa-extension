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
 * Factory for the default logging {@link PushMfaEventListener} implementation.
 */
public class LoggingPushMfaEventListenerFactory implements PushMfaEventListenerFactory {

    public static final String ID = "log";

    private static final LoggingPushMfaEventListener SINGLETON = new LoggingPushMfaEventListener();

    @Override
    public PushMfaEventListener create(KeycloakSession session) {
        return SINGLETON;
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
