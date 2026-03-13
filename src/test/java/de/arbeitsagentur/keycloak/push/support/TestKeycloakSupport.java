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

import de.arbeitsagentur.keycloak.push.resource.DpopAuthenticator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Map;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.sessions.AuthenticationSessionModel;

public final class TestKeycloakSupport {

    private TestKeycloakSupport() {}

    public static KeyWrapper rsaSigningKey(String kid) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        KeyWrapper key = new KeyWrapper();
        key.setKid(kid);
        key.setAlgorithm(Algorithm.RS256.toString());
        key.setPrivateKey(pair.getPrivate());
        key.setPublicKey(pair.getPublic());
        return key;
    }

    public static void bindNoteStores(
            AuthenticationSessionModel authSession, Map<String, String> authNotes, Map<String, String> clientNotes) {
        when(authSession.getAuthNote(any())).thenAnswer(invocation -> authNotes.get(invocation.getArgument(0)));
        when(authSession.getClientNote(any())).thenAnswer(invocation -> clientNotes.get(invocation.getArgument(0)));
        org.mockito.Mockito.doAnswer(invocation -> {
                    authNotes.put(invocation.getArgument(0), invocation.getArgument(1));
                    return null;
                })
                .when(authSession)
                .setAuthNote(any(), any());
        org.mockito.Mockito.doAnswer(invocation -> {
                    clientNotes.put(invocation.getArgument(0), invocation.getArgument(1));
                    return null;
                })
                .when(authSession)
                .setClientNote(any(), any());
        org.mockito.Mockito.doAnswer(invocation -> {
                    authNotes.remove(invocation.getArgument(0));
                    return null;
                })
                .when(authSession)
                .removeAuthNote(any());
        org.mockito.Mockito.doAnswer(invocation -> {
                    clientNotes.remove(invocation.getArgument(0));
                    return null;
                })
                .when(authSession)
                .removeClientNote(any());
    }

    public static DpopAuthenticator deviceAuthenticator(
            DpopAuthenticator.DeviceAssertion deviceAssertion, String... methods) {
        DpopAuthenticator authenticator = mock(DpopAuthenticator.class);
        String[] effectiveMethods = methods.length == 0 ? new String[] {"GET", "POST", "PUT"} : methods;
        for (String method : effectiveMethods) {
            when(authenticator.authenticate(any(), any(), eq(method))).thenReturn(deviceAssertion);
        }
        return authenticator;
    }
}
