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

package de.arbeitsagentur.keycloak.push.resource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.push.spi.PushMfaConfigProvider;
import de.arbeitsagentur.keycloak.push.support.InMemorySingleUseObjectProvider;
import de.arbeitsagentur.keycloak.push.util.PushMfaConfig;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;

class PushMfaResourceProviderTest {

    @Test
    void providerFactoryCreatesProviderWithStableId() {
        PushMfaRealmResourceProviderFactory factory = new PushMfaRealmResourceProviderFactory();
        KeycloakSession session = mock(KeycloakSession.class);

        assertEquals("push-mfa", factory.getId());
        assertInstanceOf(PushMfaRealmResourceProvider.class, factory.create(session));
    }

    @Test
    void providerReturnsResourceInstance() {
        KeycloakSession session = mock(KeycloakSession.class);
        PushMfaConfigProvider configProvider = mock(PushMfaConfigProvider.class);
        when(session.singleUseObjects()).thenReturn(new InMemorySingleUseObjectProvider());
        when(session.getProvider(PushMfaConfigProvider.class)).thenReturn(configProvider);
        when(configProvider.getConfig()).thenReturn(PushMfaConfig.fromScope(null));
        PushMfaRealmResourceProvider provider = new PushMfaRealmResourceProvider(session);

        assertInstanceOf(PushMfaResource.class, provider.getResource());
        provider.close();
    }
}
