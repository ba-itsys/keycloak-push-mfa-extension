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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.spi.event.ChallengeAcceptedEvent;
import de.arbeitsagentur.keycloak.push.spi.event.ChallengeDeniedEvent;
import de.arbeitsagentur.keycloak.push.spi.event.ChallengeResponseInvalidEvent;
import de.arbeitsagentur.keycloak.push.spi.event.EnrollmentCompletedEvent;
import de.arbeitsagentur.keycloak.push.spi.event.KeyRotatedEvent;
import de.arbeitsagentur.keycloak.push.spi.event.KeyRotationDeniedEvent;
import de.arbeitsagentur.keycloak.push.spi.event.PushMfaEventService;
import de.arbeitsagentur.keycloak.push.util.PushMfaConfig;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import de.arbeitsagentur.keycloak.push.util.PushMfaInputValidator;
import de.arbeitsagentur.keycloak.push.util.PushMfaKeyUtil;
import de.arbeitsagentur.keycloak.push.util.PushSignatureVerifier;
import de.arbeitsagentur.keycloak.push.util.TokenLogHelper;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.sse.Sse;
import jakarta.ws.rs.sse.SseEventSink;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class PushMfaResource {

    private static final Logger LOG = Logger.getLogger(PushMfaResource.class);
    private static final PushMfaConfig CONFIG = PushMfaConfig.load();
    private static final PushMfaSseDispatcher SSE_DISPATCHER =
            new PushMfaSseDispatcher(CONFIG.sse().maxConnections());
    private static final int SSE_RETRY_AFTER_SECONDS = 5;

    private final KeycloakSession session;
    private final PushChallengeStore challengeStore;
    private final DpopAuthenticator dpopAuth;
    private final SseEventEmitter sseEmitter;

    public PushMfaResource(KeycloakSession session) {
        this.session = session;
        this.challengeStore = new PushChallengeStore(session);
        this.dpopAuth = new DpopAuthenticator(session, CONFIG.dpop(), CONFIG.input());
        this.sseEmitter = new SseEventEmitter(challengeStore);
    }

    @GET
    @Path("enroll/challenges/{challengeId}/events")
    @Produces(MediaType.SERVER_SENT_EVENTS)
    public void streamEnrollmentEvents(
            @PathParam("challengeId") String challengeId,
            @QueryParam("secret") String secret,
            @Context SseEventSink sink,
            @Context Sse sse) {
        if (sink == null || sse == null) {
            return;
        }
        String cid = PushMfaInputValidator.requireUuid(challengeId, "challengeId");
        String sec =
                PushMfaInputValidator.optionalBoundedText(secret, CONFIG.sse().maxSecretLength(), "secret");
        LOG.debugf("Received enrollment SSE stream request for challenge %s", cid);

        boolean accepted = SSE_DISPATCHER.submit(
                () -> sseEmitter.emitEvents(cid, sec, sink, sse, SseEventEmitter.EventType.ENROLLMENT, null));
        if (!accepted) {
            LOG.warnf("Rejecting enrollment SSE for %s due to maxConnections=%d", cid, SSE_DISPATCHER.maxConnections());
            try (SseEventSink s = sink) {
                sseEmitter.sendStatusEvent(
                        s,
                        sse,
                        "TOO_MANY_CONNECTIONS",
                        null,
                        SseEventEmitter.EventType.ENROLLMENT,
                        SSE_RETRY_AFTER_SECONDS);
            }
        }
    }

    @POST
    @Path("enroll/complete")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response completeEnrollment(EnrollmentCompleteRequest request) {
        if (request == null) {
            throw new BadRequestException("Request body required");
        }
        String deviceToken = PushMfaInputValidator.require(request.token(), "token");
        PushMfaInputValidator.requireMaxLength(deviceToken, CONFIG.input().maxJwtLength(), "token");
        TokenLogHelper.logJwt("enroll-device-token", deviceToken);

        JWSInput deviceResponse = parseJwt(deviceToken, "enrollment token");
        JsonNode payload = parsePayload(deviceResponse, "enrollment token");
        Algorithm algorithm = deviceResponse.getHeader().getAlgorithm();
        PushMfaKeyUtil.requireSupportedAlgorithm(algorithm, "enrollment token");

        String userId = PushMfaInputValidator.requireBoundedText(
                jsonText(payload, "sub"), CONFIG.input().maxUserIdLength(), "sub");
        UserModel user = getUser(userId);

        String enrollmentId = PushMfaInputValidator.requireUuid(jsonText(payload, "enrollmentId"), "enrollmentId");
        PushChallenge challenge =
                challengeStore.get(enrollmentId).orElseThrow(() -> new NotFoundException("Challenge not found"));

        if (challenge.getType() != PushChallenge.Type.ENROLLMENT) {
            throw new BadRequestException("Challenge is not for enrollment");
        }
        if (!Objects.equals(challenge.getUserId(), user.getId())) {
            throw new ForbiddenException("Challenge does not belong to user");
        }
        if (challenge.getStatus() != PushChallengeStatus.PENDING) {
            throw new BadRequestException("Challenge already resolved or expired");
        }

        verifyTokenExpiration(payload.get("exp"), "enrollment token");

        String encodedNonce = PushMfaInputValidator.requireBoundedText(jsonText(payload, "nonce"), 256, "nonce");
        if (!Objects.equals(encodedNonce, PushChallengeStore.encodeNonce(challenge.getNonce()))) {
            throw new ForbiddenException("Nonce mismatch");
        }

        JsonNode jwkNode = payload.path("cnf").path("jwk");
        if (jwkNode.isMissingNode() || jwkNode.isNull()) {
            throw new BadRequestException("Enrollment token is missing cnf.jwk claim");
        }
        if (!jwkNode.isObject()) {
            throw new BadRequestException("Enrollment token cnf.jwk must be an object");
        }
        PushMfaInputValidator.ensurePublicJwk(jwkNode, "cnf.jwk");
        String jwkJson = jwkNode.toString();
        PushMfaInputValidator.requireMaxLength(jwkJson, CONFIG.input().maxJwkJsonLength(), "cnf.jwk");
        KeyWrapper deviceKey = PushMfaKeyUtil.keyWrapperFromNode(jwkNode);
        PushMfaKeyUtil.ensureKeyMatchesAlgorithm(deviceKey, algorithm.name());

        if (!PushSignatureVerifier.verify(deviceResponse, deviceKey)) {
            PushMfaEventService.fire(
                    session,
                    new ChallengeResponseInvalidEvent(
                            challenge.getRealmId(),
                            challenge.getUserId(),
                            challenge.getId(),
                            null,
                            "Invalid enrollment token signature",
                            Instant.now()));
            throw new ForbiddenException("Invalid enrollment token signature");
        }

        PushCredentialData data = new PushCredentialData(
                jwkJson,
                Instant.now().toEpochMilli(),
                requireField(payload, "deviceType", CONFIG.input().maxDeviceTypeLength()),
                requireField(payload, "pushProviderId", CONFIG.input().maxPushProviderIdLength()),
                requireField(payload, "pushProviderType", CONFIG.input().maxPushProviderTypeLength()),
                requireField(payload, "credentialId", CONFIG.input().maxCredentialIdLength()),
                requireField(payload, "deviceId", CONFIG.input().maxDeviceIdLength()));

        String labelClaim = jsonText(payload, "deviceLabel");
        String label = StringUtil.isBlank(labelClaim) ? PushMfaConstants.USER_CREDENTIAL_DISPLAY_NAME : labelClaim;
        label = PushMfaInputValidator.requireBoundedText(label, CONFIG.input().maxDeviceLabelLength(), "deviceLabel");

        PushCredentialService.createCredential(user, label, data);
        challengeStore.resolve(challenge.getId(), PushChallengeStatus.APPROVED);

        PushMfaEventService.fire(
                session,
                new EnrollmentCompletedEvent(
                        challenge.getRealmId(),
                        challenge.getUserId(),
                        challenge.getId(),
                        data.getCredentialId(),
                        data.getDeviceId(),
                        data.getDeviceType(),
                        Instant.now()));

        return Response.ok(Map.of("status", "enrolled")).build();
    }

    @GET
    @Path("login/pending")
    public Response listPendingChallenges(
            @QueryParam("userId") String userId, @Context HttpHeaders headers, @Context UriInfo uriInfo) {
        String normalizedUserId =
                PushMfaInputValidator.requireBoundedText(userId, CONFIG.input().maxUserIdLength(), "userId");
        DpopAuthenticator.DeviceAssertion device = dpopAuth.authenticate(headers, uriInfo, "GET");

        boolean userIdMatches = Objects.equals(device.user().getId(), normalizedUserId);
        CredentialModel deviceCredential = device.credential();

        List<LoginChallenge> pending =
                challengeStore
                        .findPendingAuthenticationForUser(
                                realm().getId(), device.user().getId())
                        .stream()
                        .filter(ch -> ch.getType() == PushChallenge.Type.AUTHENTICATION)
                        .filter(ch -> Objects.equals(ch.getCredentialId(), deviceCredential.getId()))
                        .filter(this::ensureAuthSessionActive)
                        .map(ch -> new LoginChallenge(
                                device.user().getId(),
                                device.user().getUsername(),
                                ch.getId(),
                                ch.getExpiresAt().getEpochSecond(),
                                ch.getClientId(),
                                resolveClientName(ch.getClientId()),
                                buildUserVerificationInfo(ch)))
                        .toList();

        if (!userIdMatches) {
            return Response.ok(Map.of("challenges", List.of())).build();
        }
        return Response.ok(Map.of("challenges", pending)).build();
    }

    @POST
    @Path("login/challenges/{cid}/respond")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response respondToChallenge(
            @PathParam("cid") String cid,
            ChallengeRespondRequest request,
            @Context HttpHeaders headers,
            @Context UriInfo uriInfo) {
        if (request == null) {
            throw new BadRequestException("Request body required");
        }
        String challengeId = PushMfaInputValidator.requireUuid(cid, "cid");
        PushChallenge challenge =
                challengeStore.get(challengeId).orElseThrow(() -> new NotFoundException("Challenge not found"));

        if (challenge.getType() != PushChallenge.Type.AUTHENTICATION) {
            throw new BadRequestException("Challenge is not for login");
        }
        if (challenge.getStatus() != PushChallengeStatus.PENDING) {
            throw new BadRequestException("Challenge already resolved or expired");
        }

        DpopAuthenticator.DeviceAssertion device = dpopAuth.authenticate(headers, uriInfo, "POST");
        if (!Objects.equals(device.user().getId(), challenge.getUserId())) {
            throw new ForbiddenException("Authentication token subject mismatch");
        }
        if (challenge.getCredentialId() != null
                && !Objects.equals(
                        challenge.getCredentialId(), device.credential().getId())) {
            throw new ForbiddenException("Authentication token device mismatch");
        }

        String deviceToken = PushMfaInputValidator.require(request.token(), "token");
        PushMfaInputValidator.requireMaxLength(deviceToken, CONFIG.input().maxJwtLength(), "token");
        TokenLogHelper.logJwt("login-device-token", deviceToken);

        JWSInput loginResponse = parseJwt(deviceToken, "authentication token");
        Algorithm algorithm = loginResponse.getHeader().getAlgorithm();
        PushMfaKeyUtil.requireSupportedAlgorithm(algorithm, "authentication token");
        JsonNode payload = parsePayload(loginResponse, "authentication token");

        String tokenAction = Optional.ofNullable(jsonText(payload, "action"))
                .map(String::toLowerCase)
                .orElse(PushMfaConstants.CHALLENGE_APPROVE);
        String tokenChallengeId = PushMfaInputValidator.requireUuid(jsonText(payload, "cid"), "cid");
        if (!Objects.equals(tokenChallengeId, challengeId)) {
            throw new ForbiddenException("Challenge mismatch");
        }

        PushCredentialData data = device.credentialData();
        if (StringUtil.isBlank(data.getCredentialId())) {
            throw new BadRequestException("Stored credential missing credentialId");
        }

        KeyWrapper publicKey = PushMfaKeyUtil.keyWrapperFromString(data.getPublicKeyJwk());
        PushMfaKeyUtil.ensureKeyMatchesAlgorithm(publicKey, algorithm.name());
        if (!PushSignatureVerifier.verify(loginResponse, publicKey)) {
            PushMfaEventService.fire(
                    session,
                    new ChallengeResponseInvalidEvent(
                            challenge.getRealmId(),
                            challenge.getUserId(),
                            challenge.getId(),
                            data.getCredentialId(),
                            "Invalid authentication token signature",
                            Instant.now()));
            throw new ForbiddenException("Invalid authentication token signature");
        }

        verifyTokenExpiration(payload.get("exp"), "authentication token");

        String tokenCredentialId = PushMfaInputValidator.requireBoundedText(
                jsonText(payload, "credId"), CONFIG.input().maxCredentialIdLength(), "credId");
        if (!Objects.equals(tokenCredentialId, data.getCredentialId())) {
            throw new ForbiddenException("Authentication token credential mismatch");
        }

        if (PushMfaConstants.CHALLENGE_DENY.equals(tokenAction)) {
            challengeStore.resolve(challengeId, PushChallengeStatus.DENIED);

            PushMfaEventService.fire(
                    session,
                    new ChallengeDeniedEvent(
                            challenge.getRealmId(),
                            challenge.getUserId(),
                            challenge.getId(),
                            challenge.getType(),
                            data.getCredentialId(),
                            challenge.getClientId(),
                            data.getDeviceId(),
                            Instant.now()));

            return Response.ok(Map.of("status", "denied")).build();
        }
        if (!PushMfaConstants.CHALLENGE_APPROVE.equals(tokenAction)) {
            throw new BadRequestException("Unsupported action: " + tokenAction);
        }

        verifyUserVerification(session, challenge, payload, data.getCredentialId());
        challengeStore.resolve(challengeId, PushChallengeStatus.APPROVED);

        PushMfaEventService.fire(
                session,
                new ChallengeAcceptedEvent(
                        challenge.getRealmId(),
                        challenge.getUserId(),
                        challenge.getId(),
                        challenge.getType(),
                        data.getCredentialId(),
                        challenge.getClientId(),
                        data.getDeviceId(),
                        Instant.now()));

        return Response.ok(Map.of("status", "approved")).build();
    }

    @GET
    @Path("login/challenges/{cid}/events")
    @Produces(MediaType.SERVER_SENT_EVENTS)
    public void streamLoginChallengeEvents(
            @PathParam("cid") String challengeId,
            @QueryParam("secret") String secret,
            @Context SseEventSink sink,
            @Context Sse sse) {
        if (sink == null || sse == null) {
            return;
        }
        String cid = PushMfaInputValidator.requireUuid(challengeId, "cid");
        String sec =
                PushMfaInputValidator.optionalBoundedText(secret, CONFIG.sse().maxSecretLength(), "secret");
        LOG.debugf("Received login SSE stream request for challenge %s", cid);

        boolean accepted = SSE_DISPATCHER.submit(() -> sseEmitter.emitEvents(
                cid, sec, sink, sse, SseEventEmitter.EventType.LOGIN, PushChallenge.Type.AUTHENTICATION));
        if (!accepted) {
            LOG.warnf("Rejecting login SSE for %s due to maxConnections=%d", cid, SSE_DISPATCHER.maxConnections());
            try (SseEventSink s = sink) {
                sseEmitter.sendStatusEvent(
                        s, sse, "TOO_MANY_CONNECTIONS", null, SseEventEmitter.EventType.LOGIN, SSE_RETRY_AFTER_SECONDS);
            }
        }
    }

    @PUT
    @Path("device/push-provider")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateDevicePushProvider(
            @Context HttpHeaders headers, @Context UriInfo uriInfo, UpdatePushProviderRequest request) {
        if (request == null) {
            throw new BadRequestException("Request body required");
        }
        DpopAuthenticator.DeviceAssertion device = dpopAuth.authenticate(headers, uriInfo, "PUT");
        String pushProviderId = PushMfaInputValidator.requireBoundedText(
                request.pushProviderId(), CONFIG.input().maxPushProviderIdLength(), "pushProviderId");
        String pushProviderType = PushMfaInputValidator.optionalBoundedText(
                request.pushProviderType(), CONFIG.input().maxPushProviderTypeLength(), "pushProviderType");

        PushCredentialData current = device.credentialData();
        if (StringUtil.isBlank(pushProviderType)) {
            pushProviderType = current.getPushProviderType();
        }
        if (pushProviderId.equals(current.getPushProviderId())
                && pushProviderType.equals(current.getPushProviderType())) {
            return Response.ok(Map.of("status", "unchanged")).build();
        }

        PushCredentialData updated = new PushCredentialData(
                current.getPublicKeyJwk(),
                current.getCreatedAt(),
                current.getDeviceType(),
                pushProviderId,
                pushProviderType,
                current.getCredentialId(),
                current.getDeviceId());
        PushCredentialService.updateCredential(device.user(), device.credential(), updated);
        LOG.infof(
                "Updated push provider {type=%s} for device %s (user=%s)",
                pushProviderType, current.getDeviceId(), device.user().getId());
        return Response.ok(Map.of("status", "updated")).build();
    }

    @PUT
    @Path("device/rotate-key")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response rotateDeviceKey(
            @Context HttpHeaders headers, @Context UriInfo uriInfo, RotateDeviceKeyRequest request) {
        if (request == null) {
            throw new BadRequestException("Request body required");
        }
        DpopAuthenticator.DeviceAssertion device = dpopAuth.authenticate(headers, uriInfo, "PUT");

        try {
            JsonNode jwkNode = Optional.ofNullable(request.publicKeyJwk())
                    .orElseThrow(() -> new BadRequestException("Request missing publicKeyJwk"));
            if (!jwkNode.isObject()) {
                throw new BadRequestException("publicKeyJwk must be an object");
            }
            PushMfaInputValidator.ensurePublicJwk(jwkNode, "publicKeyJwk");
            String jwkJson = jwkNode.toString();
            PushMfaInputValidator.requireMaxLength(jwkJson, CONFIG.input().maxJwkJsonLength(), "publicKeyJwk");

            KeyWrapper newKey = PushMfaKeyUtil.keyWrapperFromNode(jwkNode);
            String normalizedAlgorithm = PushMfaKeyUtil.requireAlgorithmFromJwk(jwkNode, "rotate-key request");
            PushMfaKeyUtil.ensureKeyMatchesAlgorithm(newKey, normalizedAlgorithm);

            PushCredentialData current = device.credentialData();
            PushCredentialData updated = new PushCredentialData(
                    jwkJson,
                    Instant.now().toEpochMilli(),
                    current.getDeviceType(),
                    current.getPushProviderId(),
                    current.getPushProviderType(),
                    current.getCredentialId(),
                    current.getDeviceId());
            PushCredentialService.updateCredential(device.user(), device.credential(), updated);

            PushMfaEventService.fire(
                    session,
                    new KeyRotatedEvent(
                            realm().getId(),
                            device.user().getId(),
                            current.getCredentialId(),
                            current.getDeviceId(),
                            Instant.now()));

            LOG.infof(
                    "Rotated device key for %s (user=%s)",
                    current.getDeviceId(), device.user().getId());
            return Response.ok(Map.of("status", "rotated")).build();
        } catch (BadRequestException ex) {
            PushMfaEventService.fire(
                    session,
                    new KeyRotationDeniedEvent(
                            realm().getId(),
                            device.user().getId(),
                            device.credentialData().getCredentialId(),
                            ex.getMessage(),
                            Instant.now()));
            throw ex;
        }
    }

    private RealmModel realm() {
        return session.getContext().getRealm();
    }

    private UserModel getUser(String userId) {
        UserModel user = session.users().getUserById(realm(), userId);
        if (user == null) {
            throw new NotFoundException("User not found");
        }
        return user;
    }

    private String resolveClientName(String clientId) {
        if (StringUtil.isBlank(clientId)) {
            return null;
        }
        ClientModel client = session.clients().getClientByClientId(realm(), clientId);
        if (client == null) {
            return null;
        }
        String name = client.getName();
        return StringUtil.isBlank(name) ? null : name;
    }

    private boolean ensureAuthSessionActive(PushChallenge challenge) {
        String rootSessionId = challenge.getRootSessionId();
        if (StringUtil.isBlank(rootSessionId)) {
            return true;
        }
        var root = session.authenticationSessions().getRootAuthenticationSession(realm(), rootSessionId);
        if (root != null) {
            return true;
        }
        LOG.debugf("Cleaning up stale challenge %s because auth session %s is gone", challenge.getId(), rootSessionId);
        challengeStore.remove(challenge.getId());
        return false;
    }

    private JWSInput parseJwt(String token, String description) {
        try {
            return new JWSInput(token);
        } catch (Exception ex) {
            throw new BadRequestException("Invalid " + description);
        }
    }

    private JsonNode parsePayload(JWSInput jws, String description) {
        try {
            return JsonSerialization.mapper.readTree(jws.getContent());
        } catch (Exception ex) {
            throw new BadRequestException("Unable to parse " + description);
        }
    }

    private static String jsonText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return (value == null || value.isNull()) ? null : value.asText(null);
    }

    private String requireField(JsonNode payload, String field, int maxLen) {
        return PushMfaInputValidator.requireBoundedText(jsonText(payload, field), maxLen, field);
    }

    private void verifyTokenExpiration(JsonNode expNode, String tokenDescription) {
        if (expNode == null || expNode.isNull()) {
            return;
        }
        long exp = expNode.asLong(Long.MIN_VALUE);
        if (exp != Long.MIN_VALUE && Instant.now().getEpochSecond() > exp) {
            throw new BadRequestException(tokenDescription + " expired");
        }
    }

    UserVerificationInfo buildUserVerificationInfo(PushChallenge challenge) {
        if (challenge == null) {
            return null;
        }
        return switch (challenge.getUserVerificationMode()) {
            case NUMBER_MATCH -> new UserVerificationInfo(
                    PushMfaConstants.USER_VERIFICATION_NUMBER_MATCH, challenge.getUserVerificationOptions(), null);
            case PIN -> {
                String expected = challenge.getUserVerificationValue();
                int pinLength = (!StringUtil.isBlank(expected) && expected.length() > 0)
                        ? expected.length()
                        : PushMfaConstants.DEFAULT_USER_VERIFICATION_PIN_LENGTH;
                yield new UserVerificationInfo(PushMfaConstants.USER_VERIFICATION_PIN, null, pinLength);
            }
            case NONE -> null;
        };
    }

    void verifyUserVerification(
            KeycloakSession session, PushChallenge challenge, JsonNode payload, String credentialId) {
        if (challenge == null) {
            return;
        }
        PushChallenge.UserVerificationMode mode = challenge.getUserVerificationMode();
        if (mode == null || mode == PushChallenge.UserVerificationMode.NONE) {
            return;
        }

        String expected = challenge.getUserVerificationValue();
        if (StringUtil.isBlank(expected)) {
            throw new IllegalStateException("Challenge missing expected user verification");
        }

        JsonNode verificationNode = payload == null ? null : payload.get("userVerification");
        if (verificationNode == null || verificationNode.isNull()) {
            throw new BadRequestException("Missing user verification");
        }
        if (!verificationNode.isTextual()) {
            throw new BadRequestException("Invalid user verification value");
        }
        String provided = verificationNode.textValue();
        if (StringUtil.isBlank(provided)) {
            throw new BadRequestException("Missing user verification");
        }
        if (!Objects.equals(expected, provided.trim())) {
            PushMfaEventService.fire(
                    session,
                    new ChallengeResponseInvalidEvent(
                            challenge.getRealmId(),
                            challenge.getUserId(),
                            challenge.getId(),
                            credentialId,
                            "User verification mismatch",
                            Instant.now()));
            throw new ForbiddenException("User verification mismatch");
        }
    }

    record EnrollmentCompleteRequest(@JsonProperty("token") String token) {}

    record LoginChallenge(
            @JsonProperty("userId") String userId,
            @JsonProperty("username") String username,
            @JsonProperty("cid") String cid,
            @JsonProperty("expiresAt") long expiresAt,
            @JsonProperty("clientId") String clientId,
            @JsonProperty("clientName") String clientName,
            @JsonProperty("userVerification") UserVerificationInfo userVerification) {}

    record UserVerificationInfo(
            @JsonProperty("type") String type,
            @JsonProperty("numbers") List<String> numbers,
            @JsonProperty("pinLength") Integer pinLength) {}

    record ChallengeRespondRequest(@JsonProperty("token") String token) {}

    record UpdatePushProviderRequest(
            @JsonProperty("pushProviderId") String pushProviderId,
            @JsonProperty("pushProviderType") String pushProviderType) {}

    record RotateDeviceKeyRequest(@JsonProperty("publicKeyJwk") JsonNode publicKeyJwk) {}
}
