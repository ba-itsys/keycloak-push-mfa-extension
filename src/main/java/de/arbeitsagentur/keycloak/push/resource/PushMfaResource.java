package de.arbeitsagentur.keycloak.push.resource;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
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
import jakarta.ws.rs.NotAuthorizedException;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.TokenVerifier;
import org.keycloak.TokenVerifier.Predicate;
import org.keycloak.common.VerificationException;
import org.keycloak.credential.CredentialModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.TokenUtil;
import org.keycloak.utils.StringUtil;

@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class PushMfaResource {

    private static final Logger LOG = Logger.getLogger(PushMfaResource.class);

    private static final PushMfaConfig PUSH_MFA_CONFIG = PushMfaConfig.load();
    private static final PushMfaConfig.Dpop DPOP_LIMITS = PUSH_MFA_CONFIG.dpop();
    private static final PushMfaConfig.Input INPUT_LIMITS = PUSH_MFA_CONFIG.input();
    private static final PushMfaConfig.Sse SSE_LIMITS = PUSH_MFA_CONFIG.sse();
    private static final PushMfaSseDispatcher SSE_DISPATCHER = new PushMfaSseDispatcher(SSE_LIMITS.maxConnections());

    private final KeycloakSession session;
    private final PushChallengeStore challengeStore;

    public PushMfaResource(KeycloakSession session) {
        this.session = session;
        this.challengeStore = new PushChallengeStore(session);
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
        String normalizedChallengeId = PushMfaInputValidator.requireUuid(challengeId, "challengeId");
        String normalizedSecret =
                PushMfaInputValidator.optionalBoundedText(secret, SSE_LIMITS.maxSecretLength(), "secret");
        LOG.infof("Received enrollment SSE stream request for challenge %s", normalizedChallengeId);

        boolean accepted =
                SSE_DISPATCHER.submit(() -> emitEnrollmentEvents(normalizedChallengeId, normalizedSecret, sink, sse));
        if (!accepted) {
            LOG.warnf(
                    "Rejecting enrollment SSE for %s due to maxConnections=%d",
                    normalizedChallengeId, SSE_DISPATCHER.maxConnections());
            try (SseEventSink eventSink = sink) {
                sendEnrollmentStatusEvent(eventSink, sse, "TOO_MANY_CONNECTIONS", null);
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
        PushMfaInputValidator.requireMaxLength(deviceToken, INPUT_LIMITS.maxJwtLength(), "token");
        TokenLogHelper.logJwt("enroll-device-token", deviceToken);

        JWSInput deviceResponse;
        try {
            deviceResponse = new JWSInput(deviceToken);
        } catch (Exception ex) {
            throw new BadRequestException("Invalid enrollment token");
        }

        JsonNode payload;
        try {
            payload = JsonSerialization.mapper.readTree(deviceResponse.getContent());
        } catch (Exception ex) {
            throw new BadRequestException("Unable to parse enrollment token");
        }

        Algorithm algorithm = deviceResponse.getHeader().getAlgorithm();
        PushMfaKeyUtil.requireSupportedAlgorithm(algorithm, "enrollment token");

        String userId = PushMfaInputValidator.requireBoundedText(
                jsonText(payload, "sub"), INPUT_LIMITS.maxUserIdLength(), "sub");
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

        JsonNode cnf = payload.path("cnf");
        JsonNode jwkNode = cnf.path("jwk");
        if (jwkNode.isMissingNode() || jwkNode.isNull()) {
            throw new BadRequestException("Enrollment token is missing cnf.jwk claim");
        }
        if (!jwkNode.isObject()) {
            throw new BadRequestException("Enrollment token cnf.jwk must be an object");
        }
        PushMfaInputValidator.ensurePublicJwk(jwkNode, "cnf.jwk");
        String jwkJson = jwkNode.toString();
        PushMfaInputValidator.requireMaxLength(jwkJson, INPUT_LIMITS.maxJwkJsonLength(), "cnf.jwk");
        KeyWrapper deviceKey = PushMfaKeyUtil.keyWrapperFromNode(jwkNode);
        PushMfaKeyUtil.ensureKeyMatchesAlgorithm(deviceKey, algorithm.name());

        if (!PushSignatureVerifier.verify(deviceResponse, deviceKey)) {
            throw new ForbiddenException("Invalid enrollment token signature");
        }

        String deviceType = PushMfaInputValidator.requireBoundedText(
                jsonText(payload, "deviceType"), INPUT_LIMITS.maxDeviceTypeLength(), "deviceType");
        String pushProviderId = PushMfaInputValidator.requireBoundedText(
                jsonText(payload, "pushProviderId"), INPUT_LIMITS.maxPushProviderIdLength(), "pushProviderId");
        String pushProviderType = PushMfaInputValidator.requireBoundedText(
                jsonText(payload, "pushProviderType"), INPUT_LIMITS.maxPushProviderTypeLength(), "pushProviderType");
        String credentialId = PushMfaInputValidator.requireBoundedText(
                jsonText(payload, "credentialId"), INPUT_LIMITS.maxCredentialIdLength(), "credentialId");
        String deviceId = PushMfaInputValidator.requireBoundedText(
                jsonText(payload, "deviceId"), INPUT_LIMITS.maxDeviceIdLength(), "deviceId");

        String labelClaim = jsonText(payload, "deviceLabel");
        String label = StringUtil.isBlank(labelClaim) ? PushMfaConstants.USER_CREDENTIAL_DISPLAY_NAME : labelClaim;
        label = PushMfaInputValidator.requireBoundedText(label, INPUT_LIMITS.maxDeviceLabelLength(), "deviceLabel");

        PushCredentialData data = new PushCredentialData(
                jwkJson,
                Instant.now().toEpochMilli(),
                deviceType,
                pushProviderId,
                pushProviderType,
                credentialId,
                deviceId);
        PushCredentialService.createCredential(user, label, data);
        challengeStore.resolve(challenge.getId(), PushChallengeStatus.APPROVED);

        return Response.ok(Map.of("status", "enrolled")).build();
    }

    @GET
    @Path("login/pending")
    public Response listPendingChallenges(
            @QueryParam("userId") String userId, @Context HttpHeaders headers, @Context UriInfo uriInfo) {
        String normalizedUserId =
                PushMfaInputValidator.requireBoundedText(userId, INPUT_LIMITS.maxUserIdLength(), "userId");
        DeviceAssertion device = authenticateDevice(headers, uriInfo, "GET");
        if (!Objects.equals(device.user().getId(), normalizedUserId)) {
            throw new ForbiddenException("Device token subject mismatch");
        }

        CredentialModel deviceCredential = device.credential();

        List<LoginChallenge> pending =
                challengeStore.findPendingForUser(realm().getId(), device.user().getId()).stream()
                        .filter(challenge -> challenge.getType() == PushChallenge.Type.AUTHENTICATION)
                        .filter(challenge -> Objects.equals(challenge.getCredentialId(), deviceCredential.getId()))
                        .filter(this::ensureAuthenticationSessionActive)
                        .map(challenge -> new LoginChallenge(
                                device.user().getId(),
                                device.user().getUsername(),
                                challenge.getId(),
                                challenge.getExpiresAt().getEpochSecond(),
                                challenge.getClientId(),
                                resolveClientDisplayName(challenge.getClientId()),
                                buildUserVerificationInfo(challenge)))
                        .toList();
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

        String challengeUserId = challenge.getUserId();

        if (challenge.getType() != PushChallenge.Type.AUTHENTICATION) {
            throw new BadRequestException("Challenge is not for login");
        }
        if (challenge.getStatus() != PushChallengeStatus.PENDING) {
            throw new BadRequestException("Challenge already resolved or expired");
        }

        DeviceAssertion assertion = authenticateDevice(headers, uriInfo, "POST");

        UserModel user = assertion.user();
        if (!Objects.equals(user.getId(), challengeUserId)) {
            throw new ForbiddenException("Authentication token subject mismatch");
        }

        CredentialModel credentialModel = assertion.credential();
        if (challenge.getCredentialId() != null
                && !Objects.equals(challenge.getCredentialId(), credentialModel.getId())) {
            throw new ForbiddenException("Authentication token device mismatch");
        }

        String deviceToken = PushMfaInputValidator.require(request.token(), "token");
        PushMfaInputValidator.requireMaxLength(deviceToken, INPUT_LIMITS.maxJwtLength(), "token");
        TokenLogHelper.logJwt("login-device-token", deviceToken);

        JWSInput loginResponse;
        try {
            loginResponse = new JWSInput(deviceToken);
        } catch (Exception ex) {
            throw new BadRequestException("Invalid authentication token");
        }

        Algorithm algorithm = loginResponse.getHeader().getAlgorithm();
        PushMfaKeyUtil.requireSupportedAlgorithm(algorithm, "authentication token");

        JsonNode payload;
        try {
            payload = JsonSerialization.mapper.readTree(loginResponse.getContent());
        } catch (Exception ex) {
            throw new BadRequestException("Unable to parse authentication token");
        }

        String tokenAction = Optional.ofNullable(jsonText(payload, "action"))
                .map(String::toLowerCase)
                .orElse(PushMfaConstants.CHALLENGE_APPROVE);

        String tokenChallengeId = PushMfaInputValidator.requireUuid(jsonText(payload, "cid"), "cid");
        if (!Objects.equals(tokenChallengeId, challengeId)) {
            throw new ForbiddenException("Challenge mismatch");
        }

        PushCredentialData data = assertion.credentialData();

        if (StringUtil.isBlank(data.getCredentialId())) {
            throw new BadRequestException("Stored credential missing credentialId");
        }

        KeyWrapper publicKey = PushMfaKeyUtil.keyWrapperFromString(data.getPublicKeyJwk());
        PushMfaKeyUtil.ensureKeyMatchesAlgorithm(publicKey, algorithm.name());

        if (!PushSignatureVerifier.verify(loginResponse, publicKey)) {
            throw new ForbiddenException("Invalid authentication token signature");
        }

        verifyTokenExpiration(payload.get("exp"), "authentication token");

        String tokenCredentialId = PushMfaInputValidator.requireBoundedText(
                jsonText(payload, "credId"), INPUT_LIMITS.maxCredentialIdLength(), "credId");
        if (!Objects.equals(tokenCredentialId, data.getCredentialId())) {
            throw new ForbiddenException("Authentication token credential mismatch");
        }

        if (PushMfaConstants.CHALLENGE_DENY.equals(tokenAction)) {
            challengeStore.resolve(challengeId, PushChallengeStatus.DENIED);
            return Response.ok(Map.of("status", "denied")).build();
        }

        if (!PushMfaConstants.CHALLENGE_APPROVE.equals(tokenAction)) {
            throw new BadRequestException("Unsupported action: " + tokenAction);
        }

        verifyUserVerification(challenge, payload);
        challengeStore.resolve(challengeId, PushChallengeStatus.APPROVED);
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
        String normalizedChallengeId = PushMfaInputValidator.requireUuid(challengeId, "cid");
        String normalizedSecret =
                PushMfaInputValidator.optionalBoundedText(secret, SSE_LIMITS.maxSecretLength(), "secret");
        LOG.infof("Received login SSE stream request for challenge %s", normalizedChallengeId);

        boolean accepted = SSE_DISPATCHER.submit(
                () -> emitLoginChallengeEvents(normalizedChallengeId, normalizedSecret, sink, sse));
        if (!accepted) {
            LOG.warnf(
                    "Rejecting login SSE for %s due to maxConnections=%d",
                    normalizedChallengeId, SSE_DISPATCHER.maxConnections());
            try (SseEventSink eventSink = sink) {
                sendLoginStatusEvent(eventSink, sse, "TOO_MANY_CONNECTIONS", null);
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
        DeviceAssertion device = authenticateDevice(headers, uriInfo, "PUT");
        String pushProviderId = PushMfaInputValidator.requireBoundedText(
                request.pushProviderId(), INPUT_LIMITS.maxPushProviderIdLength(), "pushProviderId");
        String pushProviderType = PushMfaInputValidator.optionalBoundedText(
                request.pushProviderType(), INPUT_LIMITS.maxPushProviderTypeLength(), "pushProviderType");
        PushCredentialData current = device.credentialData();
        if (StringUtil.isBlank(pushProviderType)) {
            pushProviderType = current.getPushProviderType();
        } else {
            pushProviderType = PushMfaInputValidator.requireBoundedText(
                    pushProviderType, INPUT_LIMITS.maxPushProviderTypeLength(), "pushProviderType");
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
        DeviceAssertion device = authenticateDevice(headers, uriInfo, "PUT");
        JsonNode jwkNode = Optional.ofNullable(request.publicKeyJwk())
                .orElseThrow(() -> new BadRequestException("Request missing publicKeyJwk"));
        if (!jwkNode.isObject()) {
            throw new BadRequestException("publicKeyJwk must be an object");
        }
        PushMfaInputValidator.ensurePublicJwk(jwkNode, "publicKeyJwk");
        String jwkJson = jwkNode.toString();
        PushMfaInputValidator.requireMaxLength(jwkJson, INPUT_LIMITS.maxJwkJsonLength(), "publicKeyJwk");

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
        LOG.infof(
                "Rotated device key for %s (user=%s)",
                current.getDeviceId(), device.user().getId());
        return Response.ok(Map.of("status", "rotated")).build();
    }

    private RealmModel realm() {
        return session.getContext().getRealm();
    }

    private String resolveClientDisplayName(String clientId) {
        if (StringUtil.isBlank(clientId)) {
            return null;
        }
        ClientModel client = session.clients().getClientByClientId(realm(), clientId);
        if (client == null) {
            return null;
        }
        String name = client.getName();
        if (StringUtil.isBlank(name)) {
            return null;
        }
        return name;
    }

    private UserModel getUser(String userId) {
        UserModel user = session.users().getUserById(realm(), userId);
        if (user == null) {
            throw new NotFoundException("User not found");
        }
        return user;
    }

    private static String jsonText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        return value.asText(null);
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

    private String requireAccessToken(HttpHeaders headers) {
        if (headers == null) {
            throw new NotAuthorizedException("DPoP access token required");
        }
        String authorization = headers.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (StringUtil.isBlank(authorization)) {
            throw new NotAuthorizedException("DPoP access token required");
        }
        String token;
        if (authorization.startsWith("DPoP ")) {
            token = authorization.replaceFirst("DPoP ", "").trim();
        } else if (authorization.startsWith("Bearer ")) {
            token = authorization.replaceFirst("Bearer ", "").trim();
        } else {
            throw new NotAuthorizedException("DPoP access token required");
        }
        if (StringUtil.isBlank(token)) {
            throw new NotAuthorizedException("DPoP access token required");
        }
        PushMfaInputValidator.requireMaxLength(token, INPUT_LIMITS.maxJwtLength(), "access token");
        return token;
    }

    private AccessToken authenticateAccessToken(String tokenString) {
        try {
            Predicate<? super AccessToken> revocationCheck = new TokenManager.TokenRevocationCheck(session);
            TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenString, AccessToken.class)
                    .withDefaultChecks()
                    .realmUrl(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm().getName()))
                    .checkActive(true)
                    .tokenType(List.of(TokenUtil.TOKEN_TYPE_BEARER, TokenUtil.TOKEN_TYPE_DPOP))
                    .withChecks(revocationCheck);

            String kid = verifier.getHeader().getKeyId();
            String alg = verifier.getHeader().getAlgorithm().name();
            SignatureVerifierContext svc =
                    session.getProvider(SignatureProvider.class, alg).verifier(kid);
            verifier.verifierContext(svc);
            return verifier.verify().getToken();
        } catch (VerificationException ex) {
            throw new NotAuthorizedException("Invalid access token", ex);
        }
    }

    private String requireDpopProof(HttpHeaders headers) {
        if (headers == null) {
            throw new NotAuthorizedException("DPoP proof required");
        }
        String value = headers.getHeaderString("DPoP");
        if (StringUtil.isBlank(value)) {
            throw new NotAuthorizedException("DPoP proof required");
        }
        String proof = value.trim();
        PushMfaInputValidator.requireMaxLength(proof, INPUT_LIMITS.maxJwtLength(), "DPoP proof");
        return proof;
    }

    private DeviceAssertion authenticateDevice(HttpHeaders headers, UriInfo uriInfo, String httpMethod) {
        String accessTokenString = requireAccessToken(headers);
        AccessToken accessToken = authenticateAccessToken(accessTokenString);
        String proof = requireDpopProof(headers);
        TokenLogHelper.logJwt("dpop-proof", proof);
        JWSInput dpop;
        try {
            dpop = new JWSInput(proof);
        } catch (Exception ex) {
            throw new BadRequestException("Invalid DPoP proof");
        }

        Algorithm algorithm = dpop.getHeader().getAlgorithm();
        PushMfaKeyUtil.requireSupportedAlgorithm(algorithm, "DPoP proof");

        String typ = dpop.getHeader().getType();
        if (typ == null || !"dpop+jwt".equalsIgnoreCase(typ)) {
            throw new BadRequestException("DPoP proof missing typ=dpop+jwt");
        }

        JsonNode payload;
        try {
            payload = JsonSerialization.mapper.readTree(dpop.getContent());
        } catch (Exception ex) {
            throw new BadRequestException("Unable to parse DPoP proof");
        }

        String htm = PushMfaInputValidator.require(jsonText(payload, "htm"), "htm");
        if (!httpMethod.equalsIgnoreCase(htm)) {
            throw new ForbiddenException("DPoP proof htm mismatch");
        }

        String htu = PushMfaInputValidator.require(jsonText(payload, "htu"), "htu");
        String actualHtu = uriInfo.getRequestUri().toString();
        if (!actualHtu.equals(htu)) {
            throw new ForbiddenException("DPoP proof htu mismatch");
        }

        long iat = payload.path("iat").asLong(Long.MIN_VALUE);
        if (iat == Long.MIN_VALUE) {
            throw new BadRequestException("DPoP proof missing iat");
        }
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - iat) > 120) {
            throw new BadRequestException("DPoP proof expired");
        }

        String jti = PushMfaInputValidator.require(jsonText(payload, "jti"), "jti");
        PushMfaInputValidator.requireMaxLength(jti, DPOP_LIMITS.jtiMaxLength(), "jti");

        String tokenSubject = PushMfaInputValidator.requireBoundedText(
                jsonText(payload, "sub"), INPUT_LIMITS.maxUserIdLength(), "sub");
        String tokenDeviceId = PushMfaInputValidator.requireBoundedText(
                jsonText(payload, "deviceId"), INPUT_LIMITS.maxDeviceIdLength(), "deviceId");

        UserModel user = getUser(tokenSubject);

        List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(user);
        if (credentials.isEmpty()) {
            throw new ForbiddenException("Device not registered for user");
        }

        CredentialModel credential = credentials.stream()
                .filter(model -> {
                    PushCredentialData credentialData = PushCredentialService.readCredentialData(model);
                    return credentialData != null && tokenDeviceId.equals(credentialData.getDeviceId());
                })
                .findFirst()
                .orElseThrow(() -> new ForbiddenException("Device not registered for user"));

        PushCredentialData credentialData = PushCredentialService.readCredentialData(credential);
        if (credentialData == null
                || credentialData.getPublicKeyJwk() == null
                || credentialData.getPublicKeyJwk().isBlank()) {
            throw new BadRequestException("Stored credential missing JWK");
        }

        KeyWrapper keyWrapper = PushMfaKeyUtil.keyWrapperFromString(credentialData.getPublicKeyJwk());
        PushMfaKeyUtil.ensureKeyMatchesAlgorithm(keyWrapper, algorithm.name());

        if (!PushSignatureVerifier.verify(dpop, keyWrapper)) {
            throw new ForbiddenException("Invalid DPoP proof signature");
        }

        AccessToken.Confirmation confirmation = accessToken.getConfirmation();
        if (confirmation == null
                || confirmation.getKeyThumbprint() == null
                || confirmation.getKeyThumbprint().isBlank()) {
            throw new ForbiddenException("Access token missing DPoP binding");
        }
        String expectedJkt = PushMfaKeyUtil.computeJwkThumbprint(credentialData.getPublicKeyJwk());
        if (!Objects.equals(expectedJkt, confirmation.getKeyThumbprint())) {
            throw new ForbiddenException("Access token DPoP binding mismatch");
        }

        if (!markDpopJtiUsed(realm().getId(), expectedJkt, jti)) {
            throw new ForbiddenException("DPoP proof replay detected");
        }

        return new DeviceAssertion(user, credential, credentialData);
    }

    private boolean markDpopJtiUsed(String realmId, String jkt, String jti) {
        SingleUseObjectProvider singleUse = session.singleUseObjects();
        if (singleUse == null) {
            throw new IllegalStateException("SingleUseObjectProvider unavailable");
        }
        String key = String.format("push-mfa:dpop:jti:%s:%s:%s", realmId, jkt, jti);
        return singleUse.putIfAbsent(key, DPOP_LIMITS.jtiTtlSeconds());
    }

    private boolean ensureAuthenticationSessionActive(PushChallenge challenge) {
        String rootSessionId = challenge.getRootSessionId();
        if (StringUtil.isBlank(rootSessionId)) {
            return true;
        }
        var root = session.authenticationSessions().getRootAuthenticationSession(realm(), rootSessionId);
        if (root != null) {
            return true;
        }
        LOG.infof("Cleaning up stale challenge %s because auth session %s is gone", challenge.getId(), rootSessionId);
        challengeStore.remove(challenge.getId());
        return false;
    }

    private UserVerificationInfo buildUserVerificationInfo(PushChallenge challenge) {
        if (challenge == null) {
            return null;
        }
        return switch (challenge.getUserVerificationMode()) {
            case NUMBER_MATCH -> new UserVerificationInfo(
                    PushMfaConstants.USER_VERIFICATION_NUMBER_MATCH, challenge.getUserVerificationOptions(), null);
            case PIN -> {
                Integer pinLength = null;
                String expected = challenge.getUserVerificationValue();
                if (!StringUtil.isBlank(expected)) {
                    pinLength = expected.length();
                }
                if (pinLength == null || pinLength <= 0) {
                    pinLength = PushMfaConstants.DEFAULT_USER_VERIFICATION_PIN_LENGTH;
                }
                yield new UserVerificationInfo(PushMfaConstants.USER_VERIFICATION_PIN, null, pinLength);
            }
            case NONE -> null;
        };
    }

    private void verifyUserVerification(PushChallenge challenge, JsonNode payload) {
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
            throw new ForbiddenException("User verification mismatch");
        }
    }

    private void emitLoginChallengeEvents(String challengeId, String secret, SseEventSink sink, Sse sse) {
        try (SseEventSink eventSink = sink) {
            LOG.infof("Starting login SSE stream for challenge %s", challengeId);
            if (StringUtil.isBlank(secret)) {
                LOG.infof("Login SSE rejected for %s due to missing secret", challengeId);
                sendLoginStatusEvent(eventSink, sse, "INVALID", null);
                return;
            }

            PushChallengeStatus lastStatus = null;
            while (!eventSink.isClosed()) {
                Optional<PushChallenge> challengeOpt = challengeStore.get(challengeId);
                if (challengeOpt.isEmpty()) {
                    LOG.infof("Login SSE challenge %s not found", challengeId);
                    sendLoginStatusEvent(eventSink, sse, "NOT_FOUND", null);
                    break;
                }
                PushChallenge challenge = challengeOpt.get();
                if (challenge.getType() != PushChallenge.Type.AUTHENTICATION) {
                    LOG.infof(
                            "Login SSE rejected for %s because challenge type is %s", challengeId, challenge.getType());
                    sendLoginStatusEvent(eventSink, sse, "BAD_TYPE", null);
                    break;
                }
                if (!Objects.equals(secret, challenge.getWatchSecret())) {
                    LOG.infof("Login SSE forbidden for %s due to secret mismatch", challengeId);
                    sendLoginStatusEvent(eventSink, sse, "FORBIDDEN", null);
                    break;
                }

                PushChallengeStatus currentStatus = challenge.getStatus();
                if (lastStatus != currentStatus) {
                    sendLoginStatusEvent(eventSink, sse, currentStatus.name(), challenge);
                    lastStatus = currentStatus;
                }

                if (currentStatus != PushChallengeStatus.PENDING) {
                    LOG.infof("Login SSE exiting for %s after reaching status %s", challengeId, currentStatus);
                    break;
                }

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    sendLoginStatusEvent(eventSink, sse, "INTERRUPTED", null);
                    LOG.infof("Login SSE interrupted for %s", challengeId);
                    break;
                }
            }
            LOG.infof("Login SSE stream closed for challenge %s", challengeId);
        } catch (Exception ex) {
            LOG.infof(ex, "Failed to stream login events for %s", challengeId);
        }
    }

    private void emitEnrollmentEvents(String challengeId, String secret, SseEventSink sink, Sse sse) {
        try (SseEventSink eventSink = sink) {
            LOG.infof("Starting enrollment SSE stream for challenge %s", challengeId);
            if (StringUtil.isBlank(secret)) {
                LOG.infof("Enrollment SSE rejected for %s due to missing secret", challengeId);
                sendEnrollmentStatusEvent(eventSink, sse, "INVALID", null);
                return;
            }

            PushChallengeStatus lastStatus = null;
            while (!eventSink.isClosed()) {
                Optional<PushChallenge> challengeOpt = challengeStore.get(challengeId);
                if (challengeOpt.isEmpty()) {
                    LOG.infof("Enrollment SSE challenge %s not found", challengeId);
                    sendEnrollmentStatusEvent(eventSink, sse, "NOT_FOUND", null);
                    break;
                }
                PushChallenge challenge = challengeOpt.get();
                if (!Objects.equals(secret, challenge.getWatchSecret())) {
                    LOG.infof("Enrollment SSE forbidden for %s due to secret mismatch", challengeId);
                    sendEnrollmentStatusEvent(eventSink, sse, "FORBIDDEN", null);
                    break;
                }

                PushChallengeStatus currentStatus = challenge.getStatus();
                if (lastStatus != currentStatus) {
                    sendEnrollmentStatusEvent(eventSink, sse, currentStatus.name(), challenge);
                    lastStatus = currentStatus;
                }

                if (currentStatus != PushChallengeStatus.PENDING) {
                    LOG.infof("Enrollment SSE exiting for %s after reaching status %s", challengeId, currentStatus);
                    break;
                }

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    sendEnrollmentStatusEvent(eventSink, sse, "INTERRUPTED", null);
                    LOG.infof("Enrollment SSE interrupted for %s", challengeId);
                    break;
                }
            }
            LOG.infof("Enrollment SSE stream closed for challenge %s", challengeId);
        } catch (Exception ex) {
            LOG.infof(ex, "Failed to stream enrollment events for %s", challengeId);
        }
    }

    private void sendLoginStatusEvent(SseEventSink sink, Sse sse, String status, PushChallenge challenge) {
        if (sink.isClosed()) {
            return;
        }
        try {
            String targetChallengeId = challenge != null ? challenge.getId() : "n/a";
            LOG.infof("Emitting login SSE status %s for challenge %s", status, targetChallengeId);
            Map<String, Object> payload = new HashMap<>();
            payload.put("status", status);
            if (challenge != null) {
                payload.put("challengeId", challenge.getId());
                payload.put("expiresAt", challenge.getExpiresAt().toString());
                payload.put("clientId", challenge.getClientId());
                if (challenge.getResolvedAt() != null) {
                    payload.put("resolvedAt", challenge.getResolvedAt().toString());
                }
            }
            String data = JsonSerialization.writeValueAsString(payload);
            sink.send(sse.newEventBuilder()
                    .name("status")
                    .data(String.class, data)
                    .build());
        } catch (Exception ex) {
            LOG.infof(
                    ex,
                    "Unable to send login SSE status %s for %s",
                    status,
                    challenge != null ? challenge.getId() : "n/a");
        }
    }

    private void sendEnrollmentStatusEvent(SseEventSink sink, Sse sse, String status, PushChallenge challenge) {
        if (sink.isClosed()) {
            return;
        }
        try {
            String targetChallengeId = challenge != null ? challenge.getId() : "n/a";
            LOG.infof("Emitting enrollment SSE status %s for challenge %s", status, targetChallengeId);
            Map<String, Object> payload = new HashMap<>();
            payload.put("status", status);
            if (challenge != null) {
                payload.put("challengeId", challenge.getId());
                payload.put("expiresAt", challenge.getExpiresAt().toString());
                if (challenge.getResolvedAt() != null) {
                    payload.put("resolvedAt", challenge.getResolvedAt().toString());
                }
            }
            String data = JsonSerialization.writeValueAsString(payload);
            sink.send(sse.newEventBuilder()
                    .name("status")
                    .data(String.class, data)
                    .build());
        } catch (Exception ex) {
            LOG.infof(
                    ex,
                    "Unable to send enrollment SSE status %s for %s",
                    status,
                    challenge != null ? challenge.getId() : "n/a");
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

    record DeviceAssertion(UserModel user, CredentialModel credential, PushCredentialData credentialData) {}
}
