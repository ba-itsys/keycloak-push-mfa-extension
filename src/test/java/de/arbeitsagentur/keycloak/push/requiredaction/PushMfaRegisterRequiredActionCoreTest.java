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

package de.arbeitsagentur.keycloak.push.requiredaction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.support.FlowTestSupport;
import de.arbeitsagentur.keycloak.push.token.PushEnrollmentRequestStore;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.credential.CredentialModel;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

class PushMfaRegisterRequiredActionCoreTest {

    private PushMfaRegisterRequiredAction action;
    private RequiredActionContext context;
    private KeycloakSession session;
    private RealmModel realm;
    private UserModel user;
    private AuthenticationSessionModel authSession;
    private LoginFormsProvider form;
    private RequiredActionConfigModel config;
    private Map<String, String> notes;
    private MultivaluedHashMap<String, String> formData;

    @BeforeEach
    void setUp() throws Exception {
        action = new PushMfaRegisterRequiredAction();
        context = mock(RequiredActionContext.class);
        FlowTestSupport.BaseContext base = FlowTestSupport.baseContext();
        session = base.session();
        realm = base.realm();
        user = base.user();
        authSession = base.authSession();
        form = base.form();
        config = new RequiredActionConfigModel();
        notes = base.authNotes();
        formData = base.formData();

        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUser()).thenReturn(user);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.form()).thenReturn(form);
        when(context.getConfig()).thenReturn(config);
        when(context.getUriInfo()).thenReturn(base.uriInfo());
        when(context.getHttpRequest()).thenReturn(base.request());
    }

    @Test
    void requiredActionChallengeCreatesChallengeAndFormAttributes() {
        action.requiredActionChallenge(context);

        assertNotNull(notes.get(PushMfaConstants.ENROLL_CHALLENGE_NOTE));
        assertNotNull(notes.get(PushMfaConstants.ENROLL_SSE_TOKEN_NOTE));
        verify(form).setAttribute("pushUsername", "demo-user");
        verify(form).setAttribute(eq("enrollEventsUrl"), any());
    }

    @Test
    void processActionRefreshAndCheckBranchesRedisplayChallenge() {
        formData.add("refresh", "true");
        action.processAction(context);
        verify(context).challenge(any(Response.class));

        formData.clear();
        formData.add("check", "true");
        action.processAction(context);
        verify(context, times(2)).challenge(any(Response.class));
    }

    @Test
    void processActionSucceedsWhenCredentialExists() {
        SubjectCredentialManager credentialManager = user.credentialManager();
        CredentialModel credential = new CredentialModel();
        credential.setType(PushMfaConstants.CREDENTIAL_TYPE);
        when(credentialManager.getStoredCredentialsByTypeStream(PushMfaConstants.CREDENTIAL_TYPE))
                .thenAnswer(invocation -> Stream.of(credential));

        action.processAction(context);

        verify(context).success();
    }

    @Test
    void fetchOrCreateAndCleanupManageChallengeNotes() {
        PushChallengeStore store = new PushChallengeStore(session);
        PushChallenge created = action.fetchOrCreateChallenge(context, authSession, store, false);
        assertNotNull(created.getId());
        assertEquals(created.getId(), notes.get(PushMfaConstants.ENROLL_CHALLENGE_NOTE));

        action.cleanupChallenge(session, authSession, store);
        assertTrue(notes.isEmpty());
    }

    @Test
    void ensureWatchableAndConfigHelpersCoverFallbackPaths() {
        PushChallengeStore store = new PushChallengeStore(session);
        PushChallenge watchless = new PushChallenge(
                "challenge-1",
                "realm-1",
                "user-1",
                new byte[] {1, 2, 3},
                null,
                null,
                null,
                null,
                Instant.now().plusSeconds(30),
                PushChallenge.Type.ENROLLMENT,
                PushChallengeStatus.PENDING,
                Instant.now(),
                null);

        PushChallenge ensured = action.ensureWatchableChallenge(context, authSession, store, watchless);
        assertNotNull(ensured.getWatchSecret());

        config.setConfig(Map.of(
                PushMfaConstants.ENROLLMENT_CHALLENGE_TTL_CONFIG, "120",
                PushMfaConstants.ENROLLMENT_APP_UNIVERSAL_LINK_CONFIG, "https://app.example/enroll",
                PushMfaConstants.ENROLLMENT_USE_REQUEST_URI_CONFIG, "true",
                PushMfaConstants.ENROLLMENT_REQUEST_URI_TTL_CONFIG, "30"));
        assertEquals(Duration.ofSeconds(120), action.resolveEnrollmentTtl(context));
        assertEquals("https://app.example/enroll", action.resolveAppUniversalLink(context));
        assertTrue(action.resolveEnrollmentUseRequestUri(context));
        assertNotNull(action.buildEnrollmentEventsUrl(context, ensured));
        assertEquals(Duration.ofSeconds(30), action.resolveEnrollmentRequestUriTtl(context, ensured));
    }

    @Test
    void requiredActionChallengeCanExposeRequestUriForQrAndSameDeviceLink() {
        config.setConfig(Map.of(
                PushMfaConstants.ENROLLMENT_USE_REQUEST_URI_CONFIG, "true",
                PushMfaConstants.ENROLLMENT_APP_UNIVERSAL_LINK_CONFIG, "https://app.example/enroll"));

        action.requiredActionChallenge(context);

        String requestHandle = notes.get(PushMfaConstants.ENROLL_REQUEST_URI_HANDLE_NOTE);
        assertNotNull(requestHandle);
        PushEnrollmentRequestStore.Entry entry = new PushEnrollmentRequestStore(session).resolve(requestHandle);
        assertNotNull(entry);

        verify(form)
                .setAttribute(
                        eq("pushQrUri"),
                        argThat(value ->
                                value instanceof String stringValue && hasAbsoluteRequestUriParameter(stringValue)));
        verify(form)
                .setAttribute(
                        eq("pushQrUri"),
                        argThat(value ->
                                value instanceof String stringValue && hasAbsoluteRequestUriParameter(stringValue)));
        verify(form)
                .setAttribute(
                        eq("enrollmentToken"),
                        argThat(value -> value instanceof String stringValue
                                && URI.create(stringValue).isAbsolute()
                                && stringValue.startsWith(
                                        "https://kc.example/realms/demo/push-mfa/enroll/request-token/")));
    }

    private static boolean hasAbsoluteRequestUriParameter(String sameDeviceUri) {
        URI uri = URI.create(sameDeviceUri);
        String query = uri.getRawQuery();
        if (query == null || query.isBlank()) {
            return false;
        }
        for (String pair : query.split("&")) {
            String[] parts = pair.split("=", 2);
            if (parts.length == 2 && "request_uri".equals(parts[0])) {
                String requestUri = URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
                URI decoded = URI.create(requestUri);
                return decoded.isAbsolute()
                        && requestUri.startsWith("https://kc.example/realms/demo/push-mfa/enroll/request-token/");
            }
        }
        return false;
    }
}
