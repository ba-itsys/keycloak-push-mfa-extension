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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.spi.PushMfaEventListener;
import de.arbeitsagentur.keycloak.push.spi.PushMfaLockoutHandler;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.lang.reflect.Field;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;

class PushMfaResourceLockoutTest {

    @Test
    void lockoutUsesConfiguredHandlerAndResolvesPendingChallenges() throws Exception {
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext context = mock(KeycloakContext.class);
        RealmModel realm = mock(RealmModel.class);
        UserModel user = mock(UserModel.class);
        CredentialModel credential = new CredentialModel();
        credential.setId("kc-cred-123");
        PushCredentialData credentialData =
                new PushCredentialData("{}", 1L, "mobile", "provider-id", "log", "cred-123", "device-456");
        PushMfaLockoutHandler handler = mock(PushMfaLockoutHandler.class);
        InMemorySingleUseObjectProvider singleUse = new InMemorySingleUseObjectProvider();

        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(realm.getId()).thenReturn("realm-123");
        when(user.getId()).thenReturn("user-123");
        when(session.singleUseObjects()).thenReturn(singleUse);
        when(session.getProvider(PushMfaLockoutHandler.class)).thenReturn(handler);
        when(session.getAllProviders(PushMfaEventListener.class)).thenReturn(Set.of());

        PushChallengeStore store = new PushChallengeStore(session);
        PushChallenge pendingChallenge = store.create(
                "realm-123",
                "user-123",
                new byte[] {1, 2, 3},
                PushChallenge.Type.AUTHENTICATION,
                Duration.ofSeconds(60),
                credential.getId(),
                "client-app",
                "secret",
                "root-session");

        PushMfaResource resource = new PushMfaResource(session);
        setField(
                resource,
                "dpopAuth",
                mockDpopAuthenticator(
                        new DpopAuthenticator.DeviceAssertion(user, credential, credentialData, "client-app")));

        Response response = resource.lockoutUser(mock(HttpHeaders.class), mock(UriInfo.class));

        assertEquals(200, response.getStatus());
        @SuppressWarnings("unchecked")
        Map<String, Object> entity = (Map<String, Object>) response.getEntity();
        assertEquals("locked_out", entity.get("status"));
        verify(handler).lockoutUser(session, realm, user, credential, credentialData, "client-app");
        verify(user, never()).setEnabled(false);

        PushChallenge resolved = store.get(pendingChallenge.getId()).orElseThrow();
        assertEquals(PushChallengeStatus.USER_LOCKED_OUT, resolved.getStatus());
    }

    @Test
    void lockoutFailsWhenNoHandlerProviderExists() throws Exception {
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext context = mock(KeycloakContext.class);
        RealmModel realm = mock(RealmModel.class);
        SingleUseObjectProvider singleUse = new InMemorySingleUseObjectProvider();
        UserModel user = mock(UserModel.class);
        CredentialModel credential = new CredentialModel();
        PushCredentialData credentialData =
                new PushCredentialData("{}", 1L, "mobile", "provider-id", "log", "cred-123", "device-456");

        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(realm.getId()).thenReturn("realm-123");
        when(session.singleUseObjects()).thenReturn(singleUse);
        when(session.getProvider(PushMfaLockoutHandler.class)).thenReturn(null);

        PushMfaResource resource = new PushMfaResource(session);
        setField(
                resource,
                "dpopAuth",
                mockDpopAuthenticator(
                        new DpopAuthenticator.DeviceAssertion(user, credential, credentialData, "client-app")));

        IllegalStateException ex = assertThrows(
                IllegalStateException.class, () -> resource.lockoutUser(mock(HttpHeaders.class), mock(UriInfo.class)));

        assertNotNull(ex.getMessage());
        assertEquals("No PushMfaLockoutHandler provider available", ex.getMessage());
    }

    private static DpopAuthenticator mockDpopAuthenticator(DpopAuthenticator.DeviceAssertion deviceAssertion) {
        DpopAuthenticator authenticator = mock(DpopAuthenticator.class);
        when(authenticator.authenticate(any(), any(), eq("POST"))).thenReturn(deviceAssertion);
        return authenticator;
    }

    private static void setField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static final class InMemorySingleUseObjectProvider implements SingleUseObjectProvider {

        private final Map<String, Map<String, String>> data = new HashMap<>();

        @Override
        public void put(String key, long lifespanSeconds, Map<String, String> value) {
            data.put(key, new HashMap<>(value));
        }

        @Override
        public Map<String, String> get(String key) {
            Map<String, String> value = data.get(key);
            return value == null ? null : new HashMap<>(value);
        }

        @Override
        public Map<String, String> remove(String key) {
            Map<String, String> removed = data.remove(key);
            return removed == null ? null : new HashMap<>(removed);
        }

        @Override
        public boolean replace(String key, Map<String, String> value) {
            if (!data.containsKey(key)) {
                return false;
            }
            data.put(key, new HashMap<>(value));
            return true;
        }

        @Override
        public boolean putIfAbsent(String key, long lifespanSeconds) {
            if (data.containsKey(key)) {
                return false;
            }
            data.put(key, new HashMap<>());
            return true;
        }

        @Override
        public boolean contains(String key) {
            return data.containsKey(key);
        }

        @Override
        public void close() {
            // no-op
        }
    }
}
