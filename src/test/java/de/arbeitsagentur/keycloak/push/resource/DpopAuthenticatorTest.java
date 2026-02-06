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
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.spi.PushMfaEventListener;
import de.arbeitsagentur.keycloak.push.spi.event.DpopAuthenticationFailedEvent;
import de.arbeitsagentur.keycloak.push.util.PushMfaConfig;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.representations.AccessToken;

/**
 * Unit tests for {@link DpopAuthenticator}.
 *
 * <p>Note: The DpopAuthenticator depends on Keycloak's TokenVerifier for access token validation,
 * which is difficult to mock in unit tests. This test class uses a testable subclass that
 * bypasses access token verification to focus on testing the DPoP proof validation logic.
 *
 * <p>For full end-to-end testing of the authentication flow including access token verification,
 * integration tests with a running Keycloak instance are recommended.
 */
class DpopAuthenticatorTest {

    private static final String REALM_ID = "test-realm";
    private static final String REALM_NAME = "test-realm";
    private static final String USER_ID = "user-123";
    private static final String DEVICE_ID = "device-456";
    private static final String HTTP_METHOD = "POST";
    private static final String REQUEST_URI =
            "https://keycloak.example.com/realms/test-realm/push-mfa/challenge/respond";
    private static final String REQUEST_PATH = "/realms/test-realm/push-mfa/challenge/respond";

    private KeycloakSession session;
    private HttpHeaders headers;
    private UriInfo uriInfo;
    private RealmModel realm;
    private UserModel user;
    private CredentialModel credential;
    private SingleUseObjectProvider singleUseObjectProvider;
    private TestableDpopAuthenticator authenticator;
    private ECKey deviceKey;
    private String publicKeyJwk;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(DpopAuthenticatorTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        // Generate a device key pair for signing DPoP proofs
        deviceKey = new ECKeyGenerator(Curve.P_256)
                .keyID("device-key-" + UUID.randomUUID())
                .algorithm(JWSAlgorithm.ES256)
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        publicKeyJwk = deviceKey.toPublicJWK().toJSONString();

        // Mock KeycloakSession and its dependencies
        session = mock(KeycloakSession.class);
        KeycloakContext context = mock(KeycloakContext.class);
        realm = mock(RealmModel.class);
        KeycloakUriInfo keycloakUriInfo = mock(KeycloakUriInfo.class);
        user = mock(UserModel.class);
        UserProvider userProvider = mock(UserProvider.class);
        singleUseObjectProvider = new InMemorySingleUseObjectProvider();

        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUri()).thenReturn(keycloakUriInfo);
        when(keycloakUriInfo.getBaseUri()).thenReturn(URI.create("https://keycloak.example.com"));
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn(REALM_NAME);
        when(session.users()).thenReturn(userProvider);
        when(userProvider.getUserById(realm, USER_ID)).thenReturn(user);
        when(session.singleUseObjects()).thenReturn(singleUseObjectProvider);

        // Mock credential
        credential = new CredentialModel();
        credential.setId("cred-789");
        credential.setType(PushMfaConstants.CREDENTIAL_TYPE);
        PushCredentialData credentialData = new PushCredentialData(
                publicKeyJwk,
                Instant.now().toEpochMilli(),
                "mobile",
                "push-token",
                "fcm",
                credential.getId(),
                DEVICE_ID);
        credential.setCredentialData(toJson(credentialData));

        SubjectCredentialManager credentialManager = mock(SubjectCredentialManager.class);
        when(user.credentialManager()).thenReturn(credentialManager);
        // Return a fresh stream on each call to avoid "stream already operated upon" error
        when(credentialManager.getStoredCredentialsByTypeStream(PushMfaConstants.CREDENTIAL_TYPE))
                .thenAnswer(invocation -> Stream.of(credential));

        // Mock request headers and URI
        headers = mock(HttpHeaders.class);
        uriInfo = mock(UriInfo.class);
        when(uriInfo.getPath()).thenReturn(REQUEST_PATH);
        when(uriInfo.getRequestUri()).thenReturn(URI.create(REQUEST_URI));

        // Create testable authenticator with default config
        PushMfaConfig.Dpop dpopConfig = new PushMfaConfig.Dpop(300, 128, 120);
        PushMfaConfig.Input inputConfig = new PushMfaConfig.Input(16384, 128, 128, 64, 128, 128, 2048, 64, 8192);

        // Create access token with DPoP binding for test
        String jkt = computeJwkThumbprint(publicKeyJwk);
        AccessToken accessToken = new AccessToken();
        accessToken.issuer("https://keycloak.example.com/realms/test-realm");
        accessToken.issuedNow();
        accessToken.exp(Instant.now().plusSeconds(300).getEpochSecond());
        accessToken.type("DPoP");
        AccessToken.Confirmation cnf = new AccessToken.Confirmation();
        cnf.setKeyThumbprint(jkt);
        accessToken.setConfirmation(cnf);

        authenticator = new TestableDpopAuthenticator(session, dpopConfig, inputConfig, accessToken);
    }

    // ==================== Access Token Validation Tests ====================

    @Test
    void missingAuthorizationHeader() {
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(null);

        NotAuthorizedException ex = assertThrows(
                NotAuthorizedException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("HTTP 401 Unauthorized", ex.getMessage());
    }

    @Test
    void emptyAuthorizationHeader() {
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("   ");

        NotAuthorizedException ex = assertThrows(
                NotAuthorizedException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("HTTP 401 Unauthorized", ex.getMessage());
    }

    @Test
    void invalidAuthorizationScheme() {
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Basic dXNlcjpwYXNz");

        NotAuthorizedException ex = assertThrows(
                NotAuthorizedException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("HTTP 401 Unauthorized", ex.getMessage());
    }

    @Test
    void nullHeaders() {
        NotAuthorizedException ex = assertThrows(
                NotAuthorizedException.class, () -> authenticator.authenticate(null, uriInfo, HTTP_METHOD));
        assertEquals("HTTP 401 Unauthorized", ex.getMessage());
    }

    // ==================== DPoP Header Validation Tests ====================

    @Test
    void missingDpopHeader() {
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(null);

        NotAuthorizedException ex = assertThrows(
                NotAuthorizedException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("HTTP 401 Unauthorized", ex.getMessage());
    }

    @Test
    void emptyDpopHeader() {
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn("  ");

        NotAuthorizedException ex = assertThrows(
                NotAuthorizedException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("HTTP 401 Unauthorized", ex.getMessage());
    }

    @Test
    void malformedDpopToken() {
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn("not-a-valid-jwt");

        BadRequestException ex = assertThrows(
                BadRequestException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("Invalid DPoP proof", ex.getMessage());
    }

    // ==================== DPoP Type Header Validation Tests ====================

    @Test
    void dpopMissingTypHeader() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(deviceKey.getKeyID())
                // Missing .type(new JOSEObjectType("dpop+jwt"))
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", HTTP_METHOD)
                .claim("htu", REQUEST_URI)
                .issueTime(Date.from(Instant.now()))
                .jwtID(UUID.randomUUID().toString())
                .subject(USER_ID)
                .claim("deviceId", DEVICE_ID)
                .build();
        SignedJWT dpop = new SignedJWT(header, claims);
        dpop.sign(new ECDSASigner(deviceKey));

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpop.serialize());

        BadRequestException ex = assertThrows(
                BadRequestException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("DPoP proof missing typ=dpop+jwt", ex.getMessage());
    }

    @Test
    void dpopWrongTypHeader() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(deviceKey.getKeyID())
                .type(JOSEObjectType.JWT) // Wrong type, should be dpop+jwt
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", HTTP_METHOD)
                .claim("htu", REQUEST_URI)
                .issueTime(Date.from(Instant.now()))
                .jwtID(UUID.randomUUID().toString())
                .subject(USER_ID)
                .claim("deviceId", DEVICE_ID)
                .build();
        SignedJWT dpop = new SignedJWT(header, claims);
        dpop.sign(new ECDSASigner(deviceKey));

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpop.serialize());

        BadRequestException ex = assertThrows(
                BadRequestException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("DPoP proof missing typ=dpop+jwt", ex.getMessage());
    }

    // ==================== HTTP Method (htm) Validation Tests ====================

    @Test
    void wrongHttpMethodInDpop() throws Exception {
        String dpopProof = createDpopProof(
                "GET", REQUEST_URI, Instant.now(), UUID.randomUUID().toString());

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        ForbiddenException ex =
                assertThrows(ForbiddenException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("DPoP proof htm mismatch", ex.getMessage());
    }

    @Test
    void missingHtmClaim() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(deviceKey.getKeyID())
                .type(new JOSEObjectType("dpop+jwt"))
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                // Missing .claim("htm", HTTP_METHOD)
                .claim("htu", REQUEST_URI)
                .issueTime(Date.from(Instant.now()))
                .jwtID(UUID.randomUUID().toString())
                .subject(USER_ID)
                .claim("deviceId", DEVICE_ID)
                .build();
        SignedJWT dpop = new SignedJWT(header, claims);
        dpop.sign(new ECDSASigner(deviceKey));

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpop.serialize());

        BadRequestException ex = assertThrows(
                BadRequestException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("Missing field: htm", ex.getMessage());
    }

    // ==================== HTTP URI (htu) Validation Tests ====================

    @Test
    void wrongUriInDpop() throws Exception {
        String dpopProof = createDpopProof(
                HTTP_METHOD,
                "https://other.example.com/wrong-path",
                Instant.now(),
                UUID.randomUUID().toString());

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        ForbiddenException ex =
                assertThrows(ForbiddenException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("DPoP proof htu mismatch", ex.getMessage());
    }

    @Test
    void missingHtuClaim() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(deviceKey.getKeyID())
                .type(new JOSEObjectType("dpop+jwt"))
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", HTTP_METHOD)
                // Missing .claim("htu", REQUEST_URI)
                .issueTime(Date.from(Instant.now()))
                .jwtID(UUID.randomUUID().toString())
                .subject(USER_ID)
                .claim("deviceId", DEVICE_ID)
                .build();
        SignedJWT dpop = new SignedJWT(header, claims);
        dpop.sign(new ECDSASigner(deviceKey));

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpop.serialize());

        BadRequestException ex = assertThrows(
                BadRequestException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("Missing field: htu", ex.getMessage());
    }

    // ==================== HTU Query/Fragment Stripping Tests (RFC 9449) ====================

    @Test
    void htuWithoutQueryMatchesRequestUriWithQuery() throws Exception {
        // RFC 9449-compliant client sends htu without query params
        URI requestUriWithQuery = URI.create(REQUEST_URI + "?userId=user-123");
        when(uriInfo.getRequestUri()).thenReturn(requestUriWithQuery);

        // DPoP proof uses base URI (no query)
        String dpopProof = createDpopProof(
                HTTP_METHOD, REQUEST_URI, Instant.now(), UUID.randomUUID().toString());

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        DpopAuthenticator.DeviceAssertion result = authenticator.authenticate(headers, uriInfo, HTTP_METHOD);
        assertNotNull(result);
    }

    @Test
    void htuWithQueryMatchesRequestUriWithQuery_backwardsCompat() throws Exception {
        // Old client sends htu with query params (backwards compatibility)
        URI requestUriWithQuery = URI.create(REQUEST_URI + "?userId=user-123");
        when(uriInfo.getRequestUri()).thenReturn(requestUriWithQuery);

        // DPoP proof also includes query params
        String dpopProof = createDpopProof(
                HTTP_METHOD,
                REQUEST_URI + "?userId=user-123",
                Instant.now(),
                UUID.randomUUID().toString());

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        DpopAuthenticator.DeviceAssertion result = authenticator.authenticate(headers, uriInfo, HTTP_METHOD);
        assertNotNull(result);
    }

    @Test
    void htuWithDifferentBasePath_rejected() throws Exception {
        // htu base path does not match, even with query stripped
        URI requestUriWithQuery = URI.create(REQUEST_URI + "?userId=user-123");
        when(uriInfo.getRequestUri()).thenReturn(requestUriWithQuery);

        String dpopProof = createDpopProof(
                HTTP_METHOD,
                "https://keycloak.example.com/realms/test-realm/push-mfa/wrong-path?userId=user-123",
                Instant.now(),
                UUID.randomUUID().toString());

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        ForbiddenException ex =
                assertThrows(ForbiddenException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("DPoP proof htu mismatch", ex.getMessage());
    }

    @Test
    void htuWithUrnUserIdEncodingDifference_strippedAndMatches() throws Exception {
        // Request URI has percent-encoded URN userId; htu uses raw colons
        // Both should match because query params are stripped from both sides
        URI requestUriEncoded = URI.create(REQUEST_URI + "?userId=urn%3Abla%3A123");
        when(uriInfo.getRequestUri()).thenReturn(requestUriEncoded);

        String dpopProof = createDpopProof(
                HTTP_METHOD,
                REQUEST_URI + "?userId=urn:bla:123",
                Instant.now(),
                UUID.randomUUID().toString());

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        DpopAuthenticator.DeviceAssertion result = authenticator.authenticate(headers, uriInfo, HTTP_METHOD);
        assertNotNull(result);
    }

    // ==================== Issued At (iat) Validation Tests ====================

    @Test
    void expiredDpopToken_iatTooOld() throws Exception {
        // Create DPoP proof with iat more than 2 minutes in the past
        Instant oldIat = Instant.now().minusSeconds(150);
        String dpopProof = createDpopProof(
                HTTP_METHOD, REQUEST_URI, oldIat, UUID.randomUUID().toString());

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        BadRequestException ex = assertThrows(
                BadRequestException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("DPoP proof expired", ex.getMessage());
    }

    @Test
    void expiredDpopToken_iatTooFarInFuture() throws Exception {
        // Create DPoP proof with iat more than 2 minutes in the future
        Instant futureIat = Instant.now().plusSeconds(150);
        String dpopProof = createDpopProof(
                HTTP_METHOD, REQUEST_URI, futureIat, UUID.randomUUID().toString());

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        BadRequestException ex = assertThrows(
                BadRequestException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("DPoP proof expired", ex.getMessage());
    }

    @Test
    void missingIatClaim() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(deviceKey.getKeyID())
                .type(new JOSEObjectType("dpop+jwt"))
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", HTTP_METHOD)
                .claim("htu", REQUEST_URI)
                // Missing .issueTime(...)
                .jwtID(UUID.randomUUID().toString())
                .subject(USER_ID)
                .claim("deviceId", DEVICE_ID)
                .build();
        SignedJWT dpop = new SignedJWT(header, claims);
        dpop.sign(new ECDSASigner(deviceKey));

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpop.serialize());

        BadRequestException ex = assertThrows(
                BadRequestException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("DPoP proof missing iat", ex.getMessage());
    }

    // ==================== JWT ID (jti) Validation Tests ====================

    @Test
    void missingJtiClaim() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(deviceKey.getKeyID())
                .type(new JOSEObjectType("dpop+jwt"))
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", HTTP_METHOD)
                .claim("htu", REQUEST_URI)
                .issueTime(Date.from(Instant.now()))
                // Missing .jwtID(...)
                .subject(USER_ID)
                .claim("deviceId", DEVICE_ID)
                .build();
        SignedJWT dpop = new SignedJWT(header, claims);
        dpop.sign(new ECDSASigner(deviceKey));

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpop.serialize());

        BadRequestException ex = assertThrows(
                BadRequestException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("Missing field: jti", ex.getMessage());
    }

    @Test
    void jtiTooLong() throws Exception {
        // Create DPoP proof with jti exceeding max length (128 chars)
        String longJti = "x".repeat(200);
        String dpopProof = createDpopProof(HTTP_METHOD, REQUEST_URI, Instant.now(), longJti);

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        BadRequestException ex = assertThrows(
                BadRequestException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("Field too long: jti", ex.getMessage());
    }

    // ==================== Replay Protection Tests ====================

    @Test
    void replayProtection_jtiReuse() throws Exception {
        String jti = UUID.randomUUID().toString();
        String dpopProof = createDpopProof(HTTP_METHOD, REQUEST_URI, Instant.now(), jti);

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        // First request should succeed
        DpopAuthenticator.DeviceAssertion result = authenticator.authenticate(headers, uriInfo, HTTP_METHOD);
        assertNotNull(result);

        // Second request with same jti should fail
        ForbiddenException ex =
                assertThrows(ForbiddenException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("DPoP proof replay detected", ex.getMessage());
    }

    // ==================== Subject (sub) Validation Tests ====================

    @Test
    void missingSubClaim() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(deviceKey.getKeyID())
                .type(new JOSEObjectType("dpop+jwt"))
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", HTTP_METHOD)
                .claim("htu", REQUEST_URI)
                .issueTime(Date.from(Instant.now()))
                .jwtID(UUID.randomUUID().toString())
                // Missing .subject(USER_ID)
                .claim("deviceId", DEVICE_ID)
                .build();
        SignedJWT dpop = new SignedJWT(header, claims);
        dpop.sign(new ECDSASigner(deviceKey));

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpop.serialize());

        BadRequestException ex = assertThrows(
                BadRequestException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("Missing field: sub", ex.getMessage());
    }

    // ==================== Device ID Validation Tests ====================

    @Test
    void missingDeviceIdClaim() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(deviceKey.getKeyID())
                .type(new JOSEObjectType("dpop+jwt"))
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", HTTP_METHOD)
                .claim("htu", REQUEST_URI)
                .issueTime(Date.from(Instant.now()))
                .jwtID(UUID.randomUUID().toString())
                .subject(USER_ID)
                // Missing .claim("deviceId", DEVICE_ID)
                .build();
        SignedJWT dpop = new SignedJWT(header, claims);
        dpop.sign(new ECDSASigner(deviceKey));

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpop.serialize());

        BadRequestException ex = assertThrows(
                BadRequestException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("Missing field: deviceId", ex.getMessage());
    }

    // ==================== User Lookup Tests ====================

    @Test
    void userNotFound() throws Exception {
        String dpopProof = createDpopProofWithUser("non-existent-user", DEVICE_ID);

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        NotFoundException ex =
                assertThrows(NotFoundException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("User not found", ex.getMessage());
    }

    // ==================== Device Registration Tests ====================

    @Test
    void deviceNotRegistered_noCredentials() throws Exception {
        String dpopProof = createValidDpopProof();

        // Mock user with no credentials
        SubjectCredentialManager emptyCredentialManager = mock(SubjectCredentialManager.class);
        when(user.credentialManager()).thenReturn(emptyCredentialManager);
        when(emptyCredentialManager.getStoredCredentialsByTypeStream(PushMfaConstants.CREDENTIAL_TYPE))
                .thenReturn(Stream.empty());

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        ForbiddenException ex =
                assertThrows(ForbiddenException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("Device not registered for user", ex.getMessage());
    }

    @Test
    void deviceNotRegistered_wrongDeviceId() throws Exception {
        String dpopProof = createDpopProofWithUser(USER_ID, "wrong-device-id");

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        ForbiddenException ex =
                assertThrows(ForbiddenException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("Device not registered for user", ex.getMessage());
    }

    // ==================== Signature Validation Tests ====================

    @Test
    void invalidDpopSignature() throws Exception {
        // Create a DPoP proof signed with a different key than what's registered
        ECKey differentKey = new ECKeyGenerator(Curve.P_256)
                .keyID("different-key")
                .algorithm(JWSAlgorithm.ES256)
                .keyUse(KeyUse.SIGNATURE)
                .generate();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(differentKey.getKeyID())
                .type(new JOSEObjectType("dpop+jwt"))
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", HTTP_METHOD)
                .claim("htu", REQUEST_URI)
                .issueTime(Date.from(Instant.now()))
                .jwtID(UUID.randomUUID().toString())
                .subject(USER_ID)
                .claim("deviceId", DEVICE_ID)
                .build();
        SignedJWT dpop = new SignedJWT(header, claims);
        dpop.sign(new ECDSASigner(differentKey));

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpop.serialize());

        ForbiddenException ex =
                assertThrows(ForbiddenException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("Invalid DPoP proof signature", ex.getMessage());
    }

    // ==================== DPoP Binding Validation Tests ====================

    @Test
    void accessTokenMissingDpopBinding() throws Exception {
        // Create authenticator with access token missing cnf claim
        PushMfaConfig.Dpop dpopConfig = new PushMfaConfig.Dpop(300, 128, 120);
        PushMfaConfig.Input inputConfig = new PushMfaConfig.Input(16384, 128, 128, 64, 128, 128, 2048, 64, 8192);

        AccessToken accessTokenWithoutBinding = new AccessToken();
        accessTokenWithoutBinding.issuer("https://keycloak.example.com/realms/test-realm");
        accessTokenWithoutBinding.issuedNow();
        accessTokenWithoutBinding.exp(Instant.now().plusSeconds(300).getEpochSecond());
        accessTokenWithoutBinding.type("Bearer");
        // Note: NOT setting confirmation/cnf

        TestableDpopAuthenticator authWithoutBinding =
                new TestableDpopAuthenticator(session, dpopConfig, inputConfig, accessTokenWithoutBinding);

        String dpopProof = createValidDpopProof();

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        ForbiddenException ex = assertThrows(
                ForbiddenException.class, () -> authWithoutBinding.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("Access token missing DPoP binding", ex.getMessage());
    }

    @Test
    void accessTokenDpopBindingMismatch() throws Exception {
        // Create a different key and update credential to use it
        ECKey differentKey = new ECKeyGenerator(Curve.P_256)
                .keyID("different-key")
                .algorithm(JWSAlgorithm.ES256)
                .keyUse(KeyUse.SIGNATURE)
                .generate();

        // Update credential to use different key
        PushCredentialData credentialData = new PushCredentialData(
                differentKey.toPublicJWK().toJSONString(),
                Instant.now().toEpochMilli(),
                "mobile",
                "push-token",
                "fcm",
                credential.getId(),
                DEVICE_ID);
        credential.setCredentialData(toJson(credentialData));

        // Sign DPoP with the different key
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(differentKey.getKeyID())
                .type(new JOSEObjectType("dpop+jwt"))
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", HTTP_METHOD)
                .claim("htu", REQUEST_URI)
                .issueTime(Date.from(Instant.now()))
                .jwtID(UUID.randomUUID().toString())
                .subject(USER_ID)
                .claim("deviceId", DEVICE_ID)
                .build();
        SignedJWT dpop = new SignedJWT(header, claims);
        dpop.sign(new ECDSASigner(differentKey));

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpop.serialize());

        // The jkt in the access token (based on original deviceKey) won't match
        // the credential's new public key thumbprint
        ForbiddenException ex =
                assertThrows(ForbiddenException.class, () -> authenticator.authenticate(headers, uriInfo, HTTP_METHOD));
        assertEquals("Access token DPoP binding mismatch", ex.getMessage());
    }

    // ==================== Successful Authentication Tests ====================

    @Test
    void validDpopTokenAuthentication() throws Exception {
        String dpopProof = createValidDpopProof();

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        DpopAuthenticator.DeviceAssertion result = authenticator.authenticate(headers, uriInfo, HTTP_METHOD);

        assertNotNull(result);
        assertEquals(user, result.user());
        assertEquals(credential, result.credential());
        assertNotNull(result.credentialData());
        assertEquals(DEVICE_ID, result.credentialData().getDeviceId());
    }

    @Test
    void validDpopWithBearerScheme() throws Exception {
        String dpopProof = createValidDpopProof();

        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        DpopAuthenticator.DeviceAssertion result = authenticator.authenticate(headers, uriInfo, HTTP_METHOD);

        assertNotNull(result);
        assertEquals(user, result.user());
    }

    // ==================== Event Credential ID Tests ====================

    @Test
    void failedEventUsesAppLevelCredentialId() throws Exception {
        // Use DIFFERENT IDs to expose the mismatch:
        // - credential.getId() returns the Keycloak CredentialModel UUID
        // - credentialData.getCredentialId() returns the app-level credential ID
        String keycloakModelId = "keycloak-model-uuid";
        String appCredentialId = "app-credential-id";

        credential.setId(keycloakModelId);
        PushCredentialData differentCredentialData = new PushCredentialData(
                publicKeyJwk, Instant.now().toEpochMilli(), "mobile", "push-token", "fcm", appCredentialId, DEVICE_ID);
        credential.setCredentialData(toJson(differentCredentialData));

        // Create access token with WRONG jkt to trigger failure after credentialData is resolved
        PushMfaConfig.Dpop dpopConfig = new PushMfaConfig.Dpop(300, 128, 120);
        PushMfaConfig.Input inputConfig = new PushMfaConfig.Input(16384, 128, 128, 64, 128, 128, 2048, 64, 8192);

        AccessToken badAccessToken = new AccessToken();
        badAccessToken.issuer("https://keycloak.example.com/realms/test-realm");
        badAccessToken.issuedNow();
        badAccessToken.exp(Instant.now().plusSeconds(300).getEpochSecond());
        badAccessToken.type("DPoP");
        AccessToken.Confirmation cnf = new AccessToken.Confirmation();
        cnf.setKeyThumbprint("wrong-thumbprint");
        badAccessToken.setConfirmation(cnf);

        TestableDpopAuthenticator badAuth =
                new TestableDpopAuthenticator(session, dpopConfig, inputConfig, badAccessToken);

        // Capture the DpopAuthenticationFailedEvent via a mock listener
        AtomicReference<DpopAuthenticationFailedEvent> capturedEvent = new AtomicReference<>();
        PushMfaEventListener listener = mock(PushMfaEventListener.class);
        doAnswer(inv -> {
                    capturedEvent.set(inv.getArgument(0));
                    return null;
                })
                .when(listener)
                .onDpopAuthenticationFailed(any());
        when(session.getAllProviders(PushMfaEventListener.class)).thenReturn(Set.of(listener));

        String dpopProof = createValidDpopProof();
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("DPoP valid-token");
        when(headers.getHeaderString("DPoP")).thenReturn(dpopProof);

        assertThrows(ForbiddenException.class, () -> badAuth.authenticate(headers, uriInfo, HTTP_METHOD));

        assertNotNull(capturedEvent.get(), "DpopAuthenticationFailedEvent should have been fired");
        assertEquals(
                appCredentialId,
                capturedEvent.get().credentialId(),
                "Event credentialId should be the app-level credential ID, not the Keycloak model UUID");
    }

    // ==================== Helper Methods ====================

    private String createValidDpopProof() throws Exception {
        return createDpopProof(
                HTTP_METHOD, REQUEST_URI, Instant.now(), UUID.randomUUID().toString());
    }

    private String createDpopProof(String method, String uri, Instant iat, String jti) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(deviceKey.getKeyID())
                .type(new JOSEObjectType("dpop+jwt"))
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", method)
                .claim("htu", uri)
                .issueTime(Date.from(iat))
                .jwtID(jti)
                .subject(USER_ID)
                .claim("deviceId", DEVICE_ID)
                .build();
        SignedJWT dpop = new SignedJWT(header, claims);
        dpop.sign(new ECDSASigner(deviceKey));
        return dpop.serialize();
    }

    private String createDpopProofWithUser(String userId, String deviceId) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(deviceKey.getKeyID())
                .type(new JOSEObjectType("dpop+jwt"))
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", HTTP_METHOD)
                .claim("htu", REQUEST_URI)
                .issueTime(Date.from(Instant.now()))
                .jwtID(UUID.randomUUID().toString())
                .subject(userId)
                .claim("deviceId", deviceId)
                .build();
        SignedJWT dpop = new SignedJWT(header, claims);
        dpop.sign(new ECDSASigner(deviceKey));
        return dpop.serialize();
    }

    private String computeJwkThumbprint(String jwkJson) throws Exception {
        com.nimbusds.jose.jwk.JWK jwk = com.nimbusds.jose.jwk.JWK.parse(jwkJson);
        return jwk.computeThumbprint().toString();
    }

    private String toJson(PushCredentialData data) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Testable subclass that bypasses actual access token verification.
     * This allows unit testing of DPoP proof validation logic without requiring
     * a full Keycloak token verification infrastructure.
     */
    private static class TestableDpopAuthenticator extends DpopAuthenticator {
        private final AccessToken mockedAccessToken;

        TestableDpopAuthenticator(
                KeycloakSession session,
                PushMfaConfig.Dpop dpopLimits,
                PushMfaConfig.Input inputLimits,
                AccessToken mockedAccessToken) {
            super(session, dpopLimits, inputLimits);
            this.mockedAccessToken = mockedAccessToken;
        }

        @Override
        protected AccessToken authenticateAccessToken(String tokenString) {
            return mockedAccessToken;
        }
    }

    /**
     * In-memory implementation of SingleUseObjectProvider for testing replay protection.
     */
    private static final class InMemorySingleUseObjectProvider implements SingleUseObjectProvider {
        private final Set<String> usedKeys = new HashSet<>();

        @Override
        public void put(String key, long lifespanSeconds, java.util.Map<String, String> value) {
            usedKeys.add(key);
        }

        @Override
        public java.util.Map<String, String> get(String key) {
            return usedKeys.contains(key) ? java.util.Collections.emptyMap() : null;
        }

        @Override
        public java.util.Map<String, String> remove(String key) {
            return usedKeys.remove(key) ? java.util.Collections.emptyMap() : null;
        }

        @Override
        public boolean replace(String key, java.util.Map<String, String> value) {
            return usedKeys.contains(key);
        }

        @Override
        public boolean putIfAbsent(String key, long lifespanSeconds) {
            return usedKeys.add(key);
        }

        @Override
        public boolean contains(String key) {
            return usedKeys.contains(key);
        }

        @Override
        public void close() {
            // no-op
        }
    }
}
