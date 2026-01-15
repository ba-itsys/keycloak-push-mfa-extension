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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.times;

import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialUtils;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

class PushCredentialServiceTest {

    private final UserModel user = Mockito.mock(UserModel.class);
    private final SubjectCredentialManager manager = Mockito.mock(SubjectCredentialManager.class);

    PushCredentialServiceTest() {
        Mockito.when(user.credentialManager()).thenReturn(manager);
    }

    @Test
    void getActiveCredentialsReturnsStoredCredentials() {
        CredentialModel model = new CredentialModel();
        Mockito.when(manager.getStoredCredentialsByTypeStream(PushMfaConstants.CREDENTIAL_TYPE))
                .thenReturn(Stream.of(model));
        List<CredentialModel> result = PushCredentialService.getActiveCredentials(user);
        assertEquals(1, result.size());
        assertSame(model, result.get(0));
    }

    @Test
    void createCredentialPersistsModel() {
        ArgumentCaptor<CredentialModel> captor = ArgumentCaptor.forClass(CredentialModel.class);
        CredentialModel persisted = new CredentialModel();
        Mockito.when(manager.createStoredCredential(Mockito.any())).thenReturn(persisted);
        PushCredentialData data = new PushCredentialData(
                "{\"kty\":\"RSA\"}",
                Instant.now().toEpochMilli(),
                "ios",
                "push-token",
                "log",
                "credential-1",
                "device-1");
        CredentialModel result = PushCredentialService.createCredential(user, "Demo Device", data);
        assertSame(persisted, result);
        Mockito.verify(manager).createStoredCredential(captor.capture());
        CredentialModel created = captor.getValue();
        assertEquals(PushMfaConstants.CREDENTIAL_TYPE, created.getType());
        assertEquals("Demo Device", created.getUserLabel());
        assertEquals("{}", created.getSecretData());
        PushCredentialData stored = PushCredentialUtils.fromJson(created.getCredentialData());
        assertEquals("device-1", stored.getDeviceId());
    }

    @Test
    void readCredentialDataParsesJson() {
        PushCredentialData data =
                new PushCredentialData("{\"kty\":\"RSA\"}", 1L, "ios", "token-1", "log", "credential-1", "device");
        CredentialModel model = new CredentialModel();
        model.setCredentialData(PushCredentialUtils.toJson(data));
        PushCredentialData read = PushCredentialService.readCredentialData(model);
        assertEquals(data.getDeviceId(), read.getDeviceId());
        assertEquals(data.getPushProviderType(), read.getPushProviderType());
    }

    @Test
    void updateCredentialRewritesStoredValue() {
        PushCredentialData data =
                new PushCredentialData("{\"kty\":\"RSA\"}", 1L, "ios", "token-2", "log", "credential-2", "device");
        CredentialModel model = new CredentialModel();
        PushCredentialService.updateCredential(user, model, data);
        Mockito.verify(manager).updateStoredCredential(model);
        PushCredentialData read = PushCredentialUtils.fromJson(model.getCredentialData());
        assertEquals("token-2", read.getPushProviderId());
    }

    @Test
    void getCredentialByIdValidatesType() {
        Mockito.when(manager.getStoredCredentialById("cred-id")).thenReturn(new CredentialModel());
        assertNull(PushCredentialService.getCredentialById(user, "cred-id"));

        CredentialModel valid = new CredentialModel();
        valid.setType(PushMfaConstants.CREDENTIAL_TYPE);
        Mockito.when(manager.getStoredCredentialById("cred-id")).thenReturn(valid);
        assertSame(valid, PushCredentialService.getCredentialById(user, "cred-id"));

        assertNull(PushCredentialService.getCredentialById(user, null));
        assertNull(PushCredentialService.getCredentialById(user, ""));
        Mockito.verify(manager, times(2)).getStoredCredentialById("cred-id");
    }
}
