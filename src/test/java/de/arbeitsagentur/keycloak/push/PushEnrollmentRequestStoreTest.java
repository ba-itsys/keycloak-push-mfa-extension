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

package de.arbeitsagentur.keycloak.push;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import de.arbeitsagentur.keycloak.push.support.InMemorySingleUseObjectProvider;
import de.arbeitsagentur.keycloak.push.token.PushEnrollmentRequestStore;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.mockito.Mockito;

class PushEnrollmentRequestStoreTest {

    @Test
    void storeResolveAndRemoveRoundTrip() {
        KeycloakSession session = Mockito.mock(KeycloakSession.class);
        Mockito.when(session.singleUseObjects()).thenReturn(new InMemorySingleUseObjectProvider());

        PushEnrollmentRequestStore store = new PushEnrollmentRequestStore(session);
        PushEnrollmentRequestStore.Entry entry =
                new PushEnrollmentRequestStore.Entry("realm-1", "user-1", "challenge-1");

        store.store("handle-1", Duration.ofSeconds(60), entry);

        PushEnrollmentRequestStore.Entry resolved = store.resolve("handle-1");
        assertNotNull(resolved);
        assertEquals("realm-1", resolved.realmId());
        assertEquals("user-1", resolved.userId());
        assertEquals("challenge-1", resolved.challengeId());

        store.remove("handle-1");
        assertNull(store.resolve("handle-1"));
    }
}
