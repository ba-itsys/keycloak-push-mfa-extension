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

package de.arbeitsagentur.keycloak.push.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.challenge.WaitChallengeState;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialUtils;
import de.arbeitsagentur.keycloak.push.spi.WaitChallengeStateProvider;
import de.arbeitsagentur.keycloak.push.support.FlowTestSupport;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.credential.CredentialModel;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;

class PushMfaAuthenticatorCoreTest {

    private TestAuthenticator authenticator;
    private AuthenticationFlowContext context;
    private KeycloakSession session;
    private RealmModel realm;
    private UserModel user;
    private AuthenticationSessionModel authSession;
    private LoginFormsProvider form;
    private AuthenticatorConfigModel config;
    private MultivaluedHashMap<String, String> formData;
    private Map<String, String> notes;

    @BeforeEach
    void setUp() throws Exception {
        authenticator = new TestAuthenticator();
        context = mock(AuthenticationFlowContext.class);
        FlowTestSupport.BaseContext base = FlowTestSupport.baseContext();
        session = base.session();
        realm = base.realm();
        user = base.user();
        authSession = base.authSession();
        form = base.form();

        config = new AuthenticatorConfigModel();
        config.setConfig(new HashMap<>());
        formData = base.formData();
        notes = base.authNotes();

        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUser()).thenReturn(user);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(context.form()).thenReturn(form);
        when(context.getUriInfo()).thenReturn(base.uriInfo());
        when(context.getHttpRequest()).thenReturn(base.request());
    }

    @Test
    void helperPredicatesWorkAsExpected() {
        assertTrue(authenticator.isChallengeCallback(false, "cid"));
        assertFalse(authenticator.isChallengeCallback(true, "cid"));
        assertTrue(authenticator.isRefreshWithExistingChallenge(false, true, "cid"));
        assertFalse(authenticator.isRefreshWithExistingChallenge(false, false, "cid"));
    }

    @Test
    void authenticateDelegatesChallengeCallbackToActionAndStoresChallengeId() {
        formData.add("challengeId", "challenge-1");

        authenticator.authenticate(context);

        assertTrue(authenticator.actionCalls > 0);
    }

    @Test
    void authenticateDelegatesRefreshWhenStoredChallengeExists() {
        notes.put(PushMfaConstants.CHALLENGE_NOTE, "stored-challenge");
        formData.add("refresh", "true");

        authenticator.authenticate(context);

        assertTrue(authenticator.actionCalls > 0);
    }

    @Test
    void authenticateWithoutCredentialSkipsMfa() {
        authenticator.authenticate(context);

        verify(context).success();
    }

    @Test
    void authenticateWithCredentialIssuesChallenge() {
        SubjectCredentialManager credentialManager = user.credentialManager();
        CredentialModel credential = credential("device-cred-1");
        when(credentialManager.getStoredCredentialsByTypeStream(PushMfaConstants.CREDENTIAL_TYPE))
                .thenAnswer(invocation -> Stream.of(credential));

        authenticator.authenticate(context);

        assertTrue(authenticator.createdChallenges.size() == 1);
        verify(context).challenge(any(Response.class));
        assertTrue(notes.containsKey(PushMfaConstants.CHALLENGE_NOTE));
    }

    @Test
    void createFormPopulatesUserVerificationAndWatchUrl() {
        PushChallenge challenge = challenge("challenge-1", PushChallengeStatus.PENDING, "watch-secret");
        CredentialModel credential = credential("device-cred-1");
        Response response = authenticator.createForm(
                form,
                context,
                challenge,
                readData(credential),
                "confirm-token",
                "app://confirm",
                "app://confirm?token=x");

        assertTrue(response.getStatus() == 200);
        verify(form).setAttribute("challengeId", "challenge-1");
        verify(form).setAttribute("pushUserVerificationMode", PushChallenge.UserVerificationMode.PIN.name());
        verify(form).setAttribute("pushUserVerificationValue", "1234");
        verify(form)
                .setAttribute(
                        eq("pushChallengeWatchUrl"),
                        contains("/realms/demo/push-mfa/login/challenges/challenge-1/events?secret=watch-secret"));
    }

    @Test
    void checkPendingChallengeLimitBlocksWhenThresholdReached() {
        CredentialModel credential = credential("device-cred-1");
        authenticator.credential = credential;
        RootAuthenticationSessionModel rootSession = mock(RootAuthenticationSessionModel.class);
        when(authSession.getParentSession()).thenReturn(rootSession);
        when(rootSession.getId()).thenReturn("root-active");
        when(session.authenticationSessions().getRootAuthenticationSession(realm, "other-root"))
                .thenReturn(mock(RootAuthenticationSessionModel.class));

        PushChallengeStore store = new PushChallengeStore(session);
        store.create(
                "realm-1",
                "user-1",
                new byte[] {1, 2, 3},
                PushChallenge.Type.AUTHENTICATION,
                Duration.ofSeconds(60),
                credential.getId(),
                "client-1",
                "secret",
                "other-root");

        config.setConfig(Map.of(PushMfaConstants.MAX_PENDING_AUTH_CHALLENGES_CONFIG, "1"));

        assertTrue(authenticator.checkPendingChallengeLimit(context));
    }

    @Test
    void expectedChallengeAndAuthSessionChecksUseRealmUserTypeAndRootSession() {
        RootAuthenticationSessionModel rootSession = mock(RootAuthenticationSessionModel.class);
        AuthenticationSessionProvider authSessions = session.authenticationSessions();
        when(authSession.getParentSession()).thenReturn(rootSession);
        when(rootSession.getId()).thenReturn("root-1");
        when(authSessions.getRootAuthenticationSession(realm, "root-1")).thenReturn(rootSession);

        PushChallenge matching = challenge("challenge-1", PushChallengeStatus.PENDING, "watch-secret");
        assertTrue(authenticator.isExpectedChallenge(context, matching));
        assertTrue(authenticator.isAuthSessionActive(context, matching));

        PushChallenge wrongRealm = new PushChallenge(
                "challenge-2",
                "other-realm",
                "user-1",
                new byte[] {1},
                null,
                null,
                null,
                "root-1",
                Instant.now().plusSeconds(60),
                PushChallenge.Type.AUTHENTICATION,
                PushChallengeStatus.PENDING,
                Instant.now(),
                null);
        assertFalse(authenticator.isExpectedChallenge(context, wrongRealm));
    }

    @Test
    void waitChallengeHelpersConsultProviderWhenEnabled() {
        config.setConfig(Map.of(
                PushMfaConstants.WAIT_CHALLENGE_ENABLED_CONFIG, "true",
                PushMfaConstants.WAIT_CHALLENGE_BASE_SECONDS_CONFIG, "5",
                PushMfaConstants.WAIT_CHALLENGE_MAX_SECONDS_CONFIG, "30",
                PushMfaConstants.WAIT_CHALLENGE_RESET_HOURS_CONFIG, "1"));

        authenticator.waitProvider.state = Optional.of(new WaitChallengeState(
                Instant.now().minusSeconds(5),
                Instant.now().minusSeconds(1),
                1,
                Instant.now().plusSeconds(30)));

        assertTrue(authenticator.checkWaitChallengeLimit(context));
        authenticator.recordWaitChallengeCreated(context);
        authenticator.resetWaitChallengeState(context);

        assertTrue(authenticator.waitProvider.challengeCreated);
        assertTrue(authenticator.waitProvider.reset);
    }

    @Test
    void handleStatusCoversTerminalBranches() {
        PushChallengeStore store = mock(PushChallengeStore.class);
        when(authSession.getParentSession()).thenReturn(null);

        authenticator.handleStatus(context, store, challenge("approved", PushChallengeStatus.APPROVED, "secret"));
        authenticator.handleStatus(context, store, challenge("denied", PushChallengeStatus.DENIED, "secret"));
        authenticator.handleStatus(context, store, challenge("locked", PushChallengeStatus.USER_LOCKED_OUT, "secret"));
        authenticator.handleStatus(context, store, challenge("expired", PushChallengeStatus.EXPIRED, "secret"));

        verify(context).success();
        verify(context, atLeastOnce()).failureChallenge(any(), any());
    }

    @Test
    void actionWithoutChallengeIdShowsInternalError() {
        authenticator.action(context);

        verify(context).challenge(any(Response.class));
    }

    @Test
    void actionWithMissingChallengeAndRetryCreatesReplacement() {
        SubjectCredentialManager credentialManager = user.credentialManager();
        CredentialModel credential = credential("device-cred-1");
        when(credentialManager.getStoredCredentialsByTypeStream(PushMfaConstants.CREDENTIAL_TYPE))
                .thenAnswer(invocation -> Stream.of(credential));
        formData.add("retry", "true");

        authenticator.action(context);

        assertTrue(authenticator.createdChallenges.size() == 1);
        verify(context).challenge(any(Response.class));
    }

    @Test
    void actionCancelsPendingChallengeAndForksFlow() {
        PushChallengeStore store = new PushChallengeStore(session);
        PushChallenge challenge = store.create(
                "realm-1",
                "user-1",
                new byte[] {1, 2, 3},
                PushChallenge.Type.AUTHENTICATION,
                Duration.ofSeconds(60),
                "kc-cred-1",
                "client-1",
                "secret",
                "root-1");
        notes.put(PushMfaConstants.CHALLENGE_NOTE, challenge.getId());
        formData.add("cancel", "true");

        authenticator.action(context);

        verify(context).forkWithErrorMessage(any());
        assertFalse(store.get(challenge.getId()).isPresent());
    }

    @Test
    void actionRefreshesPendingChallenge() {
        SubjectCredentialManager credentialManager = user.credentialManager();
        CredentialModel credential = credential("device-cred-1");
        when(credentialManager.getStoredCredentialsByTypeStream(PushMfaConstants.CREDENTIAL_TYPE))
                .thenAnswer(invocation -> Stream.of(credential));

        PushChallengeStore store = new PushChallengeStore(session);
        PushChallenge challenge = store.create(
                "realm-1",
                "user-1",
                new byte[] {1, 2, 3},
                PushChallenge.Type.AUTHENTICATION,
                Duration.ofSeconds(60),
                "kc-cred-1",
                "client-1",
                "secret",
                "other-root");
        notes.put(PushMfaConstants.CHALLENGE_NOTE, challenge.getId());
        formData.add("refresh", "true");

        authenticator.action(context);

        assertTrue(authenticator.createdChallenges.size() == 1);
        verify(context).challenge(any(Response.class));
    }

    @Test
    void actionShowsWaitingFormForPendingChallenge() {
        CredentialModel credential = credential("device-cred-1");
        authenticator.credential = credential;
        PushChallengeStore store = new PushChallengeStore(session);
        PushChallenge challenge = store.create(
                "realm-1",
                "user-1",
                new byte[] {1, 2, 3},
                PushChallenge.Type.AUTHENTICATION,
                Duration.ofSeconds(60),
                "kc-cred-1",
                "client-1",
                "secret",
                "root-1");
        notes.put(PushMfaConstants.CHALLENGE_NOTE, challenge.getId());
        when(session.authenticationSessions().getRootAuthenticationSession(realm, "root-1"))
                .thenReturn(mock(RootAuthenticationSessionModel.class));

        authenticator.action(context);

        verify(context).challenge(any(Response.class));
    }

    @Test
    void resolveCredentialAndConfiguredForUseStoredCredentialData() {
        SubjectCredentialManager credentialManager = user.credentialManager();
        CredentialModel credential = credential("device-cred-1");
        when(credentialManager.getStoredCredentialsByTypeStream(PushMfaConstants.CREDENTIAL_TYPE))
                .thenAnswer(invocation -> Stream.of(credential));

        assertTrue(authenticator.configuredFor(session, realm, user));
        assertTrue(authenticator.resolveCredential(user) != null);
        assertTrue(authenticator.requiresUser());
    }

    @Test
    void setRequiredActionsAddsActionOnlyWhenNeeded() {
        SubjectCredentialManager credentialManager = user.credentialManager();
        when(realm.getAuthenticationFlowsStream()).thenReturn(Stream.empty());
        when(user.getRequiredActionsStream()).thenReturn(Stream.empty());
        when(credentialManager.getStoredCredentialsByTypeStream(PushMfaConstants.CREDENTIAL_TYPE))
                .thenAnswer(invocation -> Stream.empty());

        authenticator.setRequiredActions(session, realm, user);
        verify(user).addRequiredAction(PushMfaConstants.REQUIRED_ACTION_ID);
    }

    private static CredentialModel credential(String deviceCredentialId) {
        CredentialModel credential = new CredentialModel();
        credential.setId("kc-cred-1");
        credential.setType(PushMfaConstants.CREDENTIAL_TYPE);
        credential.setCredentialData(PushCredentialUtils.toJson(
                new PushCredentialData("{}", 1L, "mobile", "provider", "fcm", deviceCredentialId, "device-1")));
        return credential;
    }

    private static PushCredentialData readData(CredentialModel credential) {
        return PushCredentialService.readCredentialData(credential);
    }

    private static PushChallenge challenge(String id, PushChallengeStatus status, String watchSecret) {
        return new PushChallenge(
                id,
                "realm-1",
                "user-1",
                new byte[] {1, 2, 3},
                "kc-cred-1",
                "client-1",
                watchSecret,
                "root-1",
                Instant.now().plusSeconds(60),
                PushChallenge.Type.AUTHENTICATION,
                status,
                Instant.now(),
                status == PushChallengeStatus.PENDING ? null : Instant.now(),
                PushChallenge.UserVerificationMode.PIN,
                "1234",
                List.of("12", "34", "56"));
    }

    private static final class TestAuthenticator extends PushMfaAuthenticator {
        private final RecordingWaitChallengeStateProvider waitProvider = new RecordingWaitChallengeStateProvider();
        private CredentialModel credential;
        private int actionCalls;
        private final List<PushChallenge> createdChallenges = new ArrayList<>();

        @Override
        public void action(AuthenticationFlowContext context) {
            actionCalls++;
            super.action(context);
        }

        @Override
        protected CredentialModel resolveCredentialForChallenge(UserModel user, PushChallenge ch) {
            return credential;
        }

        @Override
        protected void onChallengeCreated(AuthenticationFlowContext context, PushChallenge challenge) {
            createdChallenges.add(challenge);
        }

        @Override
        protected WaitChallengeStateProvider getWaitChallengeStateProvider(AuthenticationFlowContext context) {
            return waitProvider;
        }
    }

    private static final class RecordingWaitChallengeStateProvider implements WaitChallengeStateProvider {
        private Optional<WaitChallengeState> state = Optional.empty();
        private boolean challengeCreated;
        private boolean reset;

        @Override
        public Optional<WaitChallengeState> get(String realmId, String userId, Duration resetPeriod) {
            return state;
        }

        @Override
        public void recordChallengeCreated(
                String realmId, String userId, Duration baseWait, Duration maxWait, Duration resetPeriod) {
            challengeCreated = true;
        }

        @Override
        public void reset(String realmId, String userId) {
            reset = true;
        }

        @Override
        public void close() {}
    }
}
