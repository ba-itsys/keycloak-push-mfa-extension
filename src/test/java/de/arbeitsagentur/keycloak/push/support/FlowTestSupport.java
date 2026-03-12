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

package de.arbeitsagentur.keycloak.push.support;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import org.keycloak.credential.CredentialModel;
import org.keycloak.crypto.KeyUse;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;

public final class FlowTestSupport {

    private FlowTestSupport() {}

    public static BaseContext baseContext() throws Exception {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        UserModel user = mock(UserModel.class);
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        LoginFormsProvider form = mock(LoginFormsProvider.class);
        KeyManager keyManager = mock(KeyManager.class);
        ClientModel client = mock(ClientModel.class);
        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        HttpRequest request = mock(HttpRequest.class);
        AuthenticationSessionProvider authSessions = mock(AuthenticationSessionProvider.class);
        SubjectCredentialManager credentialManager = mock(SubjectCredentialManager.class);
        MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
        Map<String, String> authNotes = new HashMap<>();
        Map<String, String> clientNotes = new HashMap<>();

        when(session.singleUseObjects()).thenReturn(new InMemorySingleUseObjectProvider());
        when(session.authenticationSessions()).thenReturn(authSessions);
        when(session.keys()).thenReturn(keyManager);
        when(keyManager.getActiveKey(any(), eq(KeyUse.SIG), any()))
                .thenReturn(TestKeycloakSupport.rsaSigningKey("kid-1"));
        when(realm.getId()).thenReturn("realm-1");
        when(realm.getName()).thenReturn("demo");
        when(realm.getDefaultSignatureAlgorithm()).thenReturn(org.keycloak.jose.jws.Algorithm.RS256.toString());
        when(user.getId()).thenReturn("user-1");
        when(user.getUsername()).thenReturn("demo-user");
        when(user.credentialManager()).thenReturn(credentialManager);
        when(credentialManager.getStoredCredentialsByTypeStream(PushMfaConstants.CREDENTIAL_TYPE))
                .thenAnswer(invocation -> Stream.<CredentialModel>empty());
        when(request.getDecodedFormParameters()).thenReturn(formData);
        when(authSession.getClient()).thenReturn(client);
        when(client.getClientId()).thenReturn("client-1");
        when(uriInfo.getBaseUri()).thenReturn(URI.create("https://kc.example/"));
        when(uriInfo.getBaseUriBuilder()).thenAnswer(invocation -> UriBuilder.fromUri("https://kc.example/"));
        when(form.setAttribute(any(), any())).thenReturn(form);
        when(form.setError(any())).thenReturn(form);
        when(form.createForm(any())).thenReturn(Response.ok().build());
        when(form.createErrorPage(any())).thenReturn(Response.status(500).build());
        TestKeycloakSupport.bindNoteStores(authSession, authNotes, clientNotes);

        return new BaseContext(
                session,
                realm,
                user,
                authSession,
                form,
                keyManager,
                client,
                uriInfo,
                request,
                authSessions,
                credentialManager,
                formData,
                authNotes,
                clientNotes);
    }

    public record BaseContext(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            AuthenticationSessionModel authSession,
            LoginFormsProvider form,
            KeyManager keyManager,
            ClientModel client,
            KeycloakUriInfo uriInfo,
            HttpRequest request,
            AuthenticationSessionProvider authSessions,
            SubjectCredentialManager credentialManager,
            MultivaluedHashMap<String, String> formData,
            Map<String, String> authNotes,
            Map<String, String> clientNotes) {}
}
