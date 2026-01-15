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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public final class DeviceClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DEVICE_CLIENT_ID = "push-device-client";
    private static final String DEVICE_CLIENT_SECRET = "device-client-secret";

    private final URI realmBase;
    private final URI tokenEndpoint;
    private final DeviceState state;
    private final HttpClient http =
            HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    private String accessToken;

    public DeviceClient(URI baseUri, DeviceState state) {
        this.realmBase = baseUri.resolve("/realms/demo/");
        this.tokenEndpoint = realmBase.resolve("protocol/openid-connect/token");
        this.state = state;
    }

    public DeviceState state() {
        return state;
    }

    public void completeEnrollment(String enrollmentToken) throws Exception {
        SignedJWT enrollment = SignedJWT.parse(enrollmentToken);
        JWTClaimsSet claims = enrollment.getJWTClaimsSet();
        state.setUserId(claims.getSubject());
        JWTClaimsSet deviceClaims = new JWTClaimsSet.Builder()
                .claim("enrollmentId", claims.getStringClaim("enrollmentId"))
                .claim("nonce", claims.getStringClaim("nonce"))
                .claim("sub", state.userId())
                .claim("deviceType", "ios")
                .claim("pushProviderId", state.pushProviderId())
                .claim("pushProviderType", state.pushProviderType())
                .claim("credentialId", state.credentialId())
                .claim("deviceId", state.deviceId())
                .claim("deviceLabel", state.deviceLabel())
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("cnf", Map.of("jwk", state.signingKey().publicJwk().toJSONObject()))
                .build();
        SignedJWT deviceToken = sign(deviceClaims);

        HttpRequest request = HttpRequest.newBuilder(realmBase.resolve("push-mfa/enroll/complete"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(MAPPER.createObjectNode()
                        .put("token", deviceToken.serialize())
                        .toString()))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "Enrollment failed: " + response.body());
    }

    public void respondToChallenge(String confirmToken, String challengeId) throws Exception {
        String status = respondToChallenge(confirmToken, challengeId, PushMfaConstants.CHALLENGE_APPROVE);
        assertEquals("approved", status);
    }

    public String respondToChallenge(String confirmToken, String challengeId, String action) throws Exception {
        HttpResponse<String> response = respondToChallengeRaw(confirmToken, challengeId, action, null);
        assertEquals(200, response.statusCode(), () -> "Respond failed: " + response.body());
        return MAPPER.readTree(response.body()).path("status").asText();
    }

    public HttpResponse<String> respondToChallengeRaw(String confirmToken, String challengeId, String action)
            throws Exception {
        return respondToChallengeRaw(confirmToken, challengeId, action, null);
    }

    public String respondToChallenge(String confirmToken, String challengeId, String action, String userVerification)
            throws Exception {
        HttpResponse<String> response = respondToChallengeRaw(confirmToken, challengeId, action, userVerification);
        assertEquals(200, response.statusCode(), () -> "Respond failed: " + response.body());
        return MAPPER.readTree(response.body()).path("status").asText();
    }

    public HttpResponse<String> respondToChallengeRaw(
            String confirmToken, String challengeId, String action, String userVerification) throws Exception {
        ensureAccessToken();
        SignedJWT confirm = SignedJWT.parse(confirmToken);
        var confirmClaims = confirm.getJWTClaimsSet();
        String cid = Objects.requireNonNullElse(confirmClaims.getStringClaim("cid"), challengeId);
        String credId = Objects.requireNonNull(confirmClaims.getStringClaim("credId"), "Confirm token missing credId");
        assertEquals(state.credentialId(), credId, "Confirm token carried unexpected credential id");
        String tokenAction = (action == null || action.isBlank()) ? PushMfaConstants.CHALLENGE_APPROVE : action;
        String normalizedAction = tokenAction.toLowerCase();
        JWTClaimsSet.Builder loginBuilder = new JWTClaimsSet.Builder()
                .claim("cid", cid)
                .claim("credId", credId)
                .claim("deviceId", state.deviceId())
                .claim("action", normalizedAction)
                .expirationTime(Date.from(Instant.now().plusSeconds(120)));
        if (userVerification != null && !userVerification.isBlank()) {
            loginBuilder.claim("userVerification", userVerification);
        }
        JWTClaimsSet loginClaims = loginBuilder.build();
        SignedJWT loginToken = sign(loginClaims);

        URI respondUri = realmBase.resolve("push-mfa/login/challenges/" + cid + "/respond");
        HttpRequest request = HttpRequest.newBuilder(respondUri)
                .header("Authorization", "DPoP " + accessToken)
                .header("DPoP", createDpopProof("POST", respondUri))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(MAPPER.createObjectNode()
                        .put("token", loginToken.serialize())
                        .toString()))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    public String updatePushProvider(String pushProviderId, String pushProviderType) throws Exception {
        ensureAccessToken();
        URI updateUri = realmBase.resolve("push-mfa/device/push-provider");
        var body = MAPPER.createObjectNode()
                .put("pushProviderId", pushProviderId)
                .put("pushProviderType", pushProviderType);
        HttpRequest request = HttpRequest.newBuilder(updateUri)
                .header("Authorization", "DPoP " + accessToken)
                .header("DPoP", createDpopProof("PUT", updateUri))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "Update push provider failed: " + response.body());
        JsonNode result = MAPPER.readTree(response.body());
        String status = result.path("status").asText();
        if ("updated".equalsIgnoreCase(status)) {
            state.updatePushProvider(pushProviderId, pushProviderType);
        }
        return status;
    }

    public String rotateDeviceKey(DeviceSigningKey newKey) throws Exception {
        ensureAccessToken();
        URI rotateUri = realmBase.resolve("push-mfa/device/rotate-key");
        JsonNode jwkNode = MAPPER.readTree(newKey.publicJwk().toJSONString());
        var body = MAPPER.createObjectNode();
        body.set("publicKeyJwk", jwkNode);
        HttpRequest request = HttpRequest.newBuilder(rotateUri)
                .header("Authorization", "DPoP " + accessToken)
                .header("DPoP", createDpopProof("PUT", rotateUri))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "Rotate key failed: " + response.body());
        JsonNode result = MAPPER.readTree(response.body());
        String status = result.path("status").asText();
        if ("rotated".equalsIgnoreCase(status)) {
            state.updateKey(newKey);
            accessToken = null;
        }
        return status;
    }

    public JsonNode fetchPendingChallenges() throws Exception {
        ensureAccessToken();
        URI pendingUri = realmBase.resolve("push-mfa/login/pending?userId=" + urlEncode(state.userId()));
        HttpRequest request = HttpRequest.newBuilder(pendingUri)
                .header("Authorization", "DPoP " + accessToken)
                .header("DPoP", createDpopProof("GET", pendingUri))
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "Pending fetch failed: " + response.body());
        return MAPPER.readTree(response.body()).path("challenges");
    }

    private SignedJWT sign(JWTClaimsSet claims) throws Exception {
        DeviceSigningKey signingKey = state.signingKey();
        JWSHeader header = new JWSHeader.Builder(signingKey.algorithm())
                .type(JOSEObjectType.JWT)
                .keyID(signingKey.keyId())
                .build();
        SignedJWT token = new SignedJWT(header, claims);
        token.sign(signingKey.signer());
        return token;
    }

    private void ensureAccessToken() throws Exception {
        if (accessToken != null) {
            return;
        }
        HttpRequest request = HttpRequest.newBuilder(tokenEndpoint)
                .header("DPoP", createDpopProof("POST", tokenEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials&client_id="
                        + urlEncode(DEVICE_CLIENT_ID) + "&client_secret=" + urlEncode(DEVICE_CLIENT_SECRET)))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "Token request failed: " + response.body());
        JsonNode json = MAPPER.readTree(response.body());
        accessToken = json.path("access_token").asText();
        assertNotNull(accessToken);
    }

    private String createDpopProof(String method, URI uri) throws Exception {
        return createDpopProof(method, uri, UUID.randomUUID().toString());
    }

    public String createDpopProof(String method, URI uri, String jti) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", method)
                .claim("htu", uri.toString())
                .claim("sub", state.userId())
                .claim("deviceId", state.deviceId())
                .claim("iat", Instant.now().getEpochSecond())
                .claim("jti", jti)
                .build();
        DeviceSigningKey signingKey = state.signingKey();
        SignedJWT proof = new SignedJWT(
                new JWSHeader.Builder(signingKey.algorithm())
                        .type(new JOSEObjectType("dpop+jwt"))
                        .jwk(signingKey.publicJwk())
                        .keyID(signingKey.keyId())
                        .build(),
                claims);
        proof.sign(signingKey.signer());
        return proof.serialize();
    }

    public String accessToken() throws Exception {
        ensureAccessToken();
        return accessToken;
    }

    public HttpResponse<String> sendRawChallengeResponse(String challengeId, String loginTokenJwt) throws Exception {
        ensureAccessToken();
        URI respondUri = realmBase.resolve("push-mfa/login/challenges/" + challengeId + "/respond");
        HttpRequest request = HttpRequest.newBuilder(respondUri)
                .header("Authorization", "DPoP " + accessToken)
                .header("DPoP", createDpopProof("POST", respondUri))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        MAPPER.createObjectNode().put("token", loginTokenJwt).toString()))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    public SignedJWT createLoginToken(
            String challengeId, String credentialId, String deviceId, String action, String userVerification)
            throws Exception {
        String normalizedAction =
                (action == null || action.isBlank()) ? PushMfaConstants.CHALLENGE_APPROVE : action.toLowerCase();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .claim("cid", challengeId)
                .claim("credId", credentialId)
                .claim("deviceId", deviceId)
                .claim("action", normalizedAction)
                .expirationTime(Date.from(Instant.now().plusSeconds(120)));
        if (userVerification != null && !userVerification.isBlank()) {
            builder.claim("userVerification", userVerification);
        }
        return sign(builder.build());
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
