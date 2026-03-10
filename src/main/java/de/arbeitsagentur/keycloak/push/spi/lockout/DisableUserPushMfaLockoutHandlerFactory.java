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

package de.arbeitsagentur.keycloak.push.spi.lockout;

import de.arbeitsagentur.keycloak.push.spi.PushMfaLockoutHandler;
import de.arbeitsagentur.keycloak.push.spi.PushMfaLockoutHandlerFactory;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Default lockout handler that preserves the current behavior.
 */
public class DisableUserPushMfaLockoutHandlerFactory implements PushMfaLockoutHandlerFactory {

    public static final String ID = "default";

    private static final DisableUserPushMfaLockoutHandler SINGLETON = new DisableUserPushMfaLockoutHandler();

    @Override
    public PushMfaLockoutHandler create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // no-op
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return ID;
    }
}
