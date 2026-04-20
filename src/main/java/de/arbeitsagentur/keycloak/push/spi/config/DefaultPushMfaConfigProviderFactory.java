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

package de.arbeitsagentur.keycloak.push.spi.config;

import de.arbeitsagentur.keycloak.push.spi.PushMfaConfigProvider;
import de.arbeitsagentur.keycloak.push.spi.PushMfaConfigProviderFactory;
import de.arbeitsagentur.keycloak.push.util.PushMfaConfig;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class DefaultPushMfaConfigProviderFactory implements PushMfaConfigProviderFactory {

    public static final String ID = "default";

    private static final List<ProviderConfigProperty> CONFIG_METADATA = PushMfaConfig.providerConfigMetadata();

    private volatile PushMfaConfig config = PushMfaConfig.fromScope(null);

    @Override
    public PushMfaConfigProvider create(KeycloakSession session) {
        return new DefaultPushMfaConfigProvider(config);
    }

    @Override
    public void init(Config.Scope config) {
        this.config = PushMfaConfig.fromScope(config);
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

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return CONFIG_METADATA;
    }
}
