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

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.spi.event.DpopAuthenticationFailedEvent;
import de.arbeitsagentur.keycloak.push.spi.event.PushMfaEventService;
import de.arbeitsagentur.keycloak.push.util.PushMfaConfig;
import de.arbeitsagentur.keycloak.push.util.PushMfaInputValidator;
import de.arbeitsagentur.keycloak.push.util.PushMfaKeyUtil;
import de.arbeitsagentur.keycloak.push.util.PushSignatureVerifier;
import de.arbeitsagentur.keycloak.push.util.StorageKeyUtil;
import de.arbeitsagentur.keycloak.push.util.TokenLogHelper;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.credential.CredentialModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSInput;
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

/** Helper for DPoP-based device authentication. */
public class DpopAuthenticator {

    private final KeycloakSession session;
    private final PushMfaConfig.Dpop dpopLimits;
    private final PushMfaConfig.Input inputLimits;

    public DpopAuthenticator(KeycloakSession session, PushMfaConfig.Dpop dpopLimits, PushMfaConfig.Input inputLimits) {
        this.session = session;
        this.dpopLimits = dpopLimits;
        this.inputLimits = inputLimits;
    }

    private RealmModel realm() {
        return session.getContext().getRealm();
    }

    public record DeviceAssertion(
            UserModel user, CredentialModel credential, PushCredentialData credentialData, String clientId) {}

    public record PublicKeyAssertion(String userId, String deviceId, String clientId) {}

    private record ParsedDpopProof(
            JWSInput proof, Algorithm algorithm, String userId, String deviceId, String jti, String ath) {}

    public DeviceAssertion authenticate(HttpHeaders headers, UriInfo uriInfo, String httpMethod) {
        AuthContext ctx = new AuthContext(httpMethod, uriInfo.getPath());

        try {
            String accessTokenString = requireAccessToken(headers);
            AccessToken accessToken = authenticateAccessToken(accessTokenString);
            ctx.clientId = extractClientId(accessToken);
            ParsedDpopProof parsedProof = parseDpopProof(headers, uriInfo, httpMethod);
            ctx.userId = parsedProof.userId();

            UserModel user = getUser(parsedProof.userId());

            List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(user);
            if (credentials.isEmpty()) {
                throw new ForbiddenException("Device not registered for user");
            }

            CredentialModel credential = credentials.stream()
                    .filter(model -> {
                        PushCredentialData credentialData = PushCredentialService.readCredentialData(model);
                        return credentialData != null && parsedProof.deviceId().equals(credentialData.getDeviceId());
                    })
                    .findFirst()
                    .orElseThrow(() -> new ForbiddenException("Device not registered for user"));

            PushCredentialData credentialData = PushCredentialService.readCredentialData(credential);
            if (credentialData == null
                    || credentialData.getPublicKeyJwk() == null
                    || credentialData.getPublicKeyJwk().isBlank()) {
                throw new BadRequestException("Stored credential missing JWK");
            }

            ctx.deviceCredentialId = credentialData.getDeviceCredentialId();

            verifyProofWithPublicKey(accessTokenString, accessToken, parsedProof, credentialData.getPublicKeyJwk());

            return new DeviceAssertion(user, credential, credentialData, ctx.clientId);
        } catch (BadRequestException | ForbiddenException | NotAuthorizedException | NotFoundException ex) {
            fireAuthFailedEvent(ctx, ex.getMessage());
            throw ex;
        }
    }

    public PublicKeyAssertion authenticateAgainstPublicKey(
            HttpHeaders headers,
            UriInfo uriInfo,
            String httpMethod,
            String publicKeyJwk,
            String expectedUserId,
            String expectedDeviceId) {
        AuthContext ctx = new AuthContext(httpMethod, uriInfo.getPath());

        try {
            // Enrollment has no stored credential yet. Reuse the normal DPoP validation path,
            // but bind it to the posted `cnf.jwk` instead of a persisted device key.
            String accessTokenString = requireAccessToken(headers);
            AccessToken accessToken = authenticateAccessToken(accessTokenString);
            ctx.clientId = extractClientId(accessToken);
            ParsedDpopProof parsedProof = parseDpopProof(headers, uriInfo, httpMethod);
            ctx.userId = parsedProof.userId();

            if (!Objects.equals(expectedUserId, parsedProof.userId())) {
                throw new ForbiddenException("DPoP proof sub mismatch");
            }
            if (!Objects.equals(expectedDeviceId, parsedProof.deviceId())) {
                throw new ForbiddenException("DPoP proof deviceId mismatch");
            }

            verifyProofWithPublicKey(accessTokenString, accessToken, parsedProof, publicKeyJwk);

            return new PublicKeyAssertion(parsedProof.userId(), parsedProof.deviceId(), ctx.clientId);
        } catch (BadRequestException | ForbiddenException | NotAuthorizedException | NotFoundException ex) {
            fireAuthFailedEvent(ctx, ex.getMessage());
            throw ex;
        }
    }

    public String authenticateAccessTokenOnly(HttpHeaders headers, UriInfo uriInfo, String httpMethod) {
        AuthContext ctx = new AuthContext(httpMethod, uriInfo.getPath());

        try {
            String accessTokenString = requireAccessToken(headers);
            AccessToken accessToken = authenticateAccessToken(accessTokenString);
            ctx.userId = accessToken.getSubject();
            ctx.clientId = extractClientId(accessToken);
            return ctx.clientId;
        } catch (BadRequestException | ForbiddenException | NotAuthorizedException | NotFoundException ex) {
            fireAuthFailedEvent(ctx, ex.getMessage());
            throw ex;
        }
    }

    /** Mutable context for tracking auth progress (used for event reporting). */
    private static class AuthContext {
        final String httpMethod;
        final String requestPath;
        String userId;
        String clientId;
        String deviceCredentialId;

        AuthContext(String httpMethod, String requestPath) {
            this.httpMethod = httpMethod;
            this.requestPath = requestPath;
        }
    }

    private void fireAuthFailedEvent(AuthContext ctx, String reason) {
        PushMfaEventService.fire(
                session,
                new DpopAuthenticationFailedEvent(
                        realm().getId(),
                        ctx.userId,
                        ctx.deviceCredentialId,
                        ctx.clientId,
                        reason,
                        ctx.httpMethod,
                        ctx.requestPath,
                        Instant.now()));
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
            // Bearer token is intentionally accepted alongside DPoP for backwards
            // compatibility with existing client implementations that may send
            // DPoP-bound tokens using the Bearer scheme instead of the DPoP scheme.
            token = authorization.replaceFirst("Bearer ", "").trim();
        } else {
            throw new NotAuthorizedException("DPoP access token required");
        }
        if (StringUtil.isBlank(token)) {
            throw new NotAuthorizedException("DPoP access token required");
        }
        PushMfaInputValidator.requireMaxLength(token, inputLimits.maxJwtLength(), "access token");
        return token;
    }

    protected AccessToken authenticateAccessToken(String tokenString) {
        try {
            TokenVerifier.Predicate<? super AccessToken> revocationCheck =
                    new TokenManager.TokenRevocationCheck(session);
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
        PushMfaInputValidator.requireMaxLength(proof, inputLimits.maxJwtLength(), "DPoP proof");
        return proof;
    }

    private ParsedDpopProof parseDpopProof(HttpHeaders headers, UriInfo uriInfo, String httpMethod) {
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
        String actualHtu = stripQueryAndFragment(uriInfo.getRequestUri().toString());
        String normalizedHtu = stripQueryAndFragment(htu);
        if (!actualHtu.equals(normalizedHtu)) {
            throw new ForbiddenException("DPoP proof htu mismatch");
        }

        long iat = payload.path("iat").asLong(Long.MIN_VALUE);
        if (iat == Long.MIN_VALUE) {
            throw new BadRequestException("DPoP proof missing iat");
        }
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - iat) > dpopLimits.iatToleranceSeconds()) {
            throw new BadRequestException("DPoP proof expired");
        }

        String jti = PushMfaInputValidator.require(jsonText(payload, "jti"), "jti");
        PushMfaInputValidator.requireMaxLength(jti, dpopLimits.jtiMaxLength(), "jti");
        String ath = PushMfaInputValidator.optionalBoundedText(jsonText(payload, "ath"), 128, "ath");

        String userId = PushMfaInputValidator.requireBoundedText(
                jsonText(payload, "sub"), inputLimits.maxUserIdLength(), "sub");
        String deviceId = PushMfaInputValidator.requireBoundedText(
                jsonText(payload, "deviceId"), inputLimits.maxDeviceIdLength(), "deviceId");
        return new ParsedDpopProof(dpop, algorithm, userId, deviceId, jti, ath);
    }

    private void verifyProofWithPublicKey(
            String accessTokenString, AccessToken accessToken, ParsedDpopProof parsedProof, String publicKeyJwk) {
        KeyWrapper keyWrapper = PushMfaKeyUtil.keyWrapperFromString(publicKeyJwk);
        PushMfaKeyUtil.ensureKeyMatchesAlgorithm(
                keyWrapper, parsedProof.algorithm().name());

        if (!PushSignatureVerifier.verify(parsedProof.proof(), keyWrapper)) {
            throw new ForbiddenException("Invalid DPoP proof signature");
        }

        AccessToken.Confirmation confirmation = accessToken.getConfirmation();
        if (confirmation == null
                || confirmation.getKeyThumbprint() == null
                || confirmation.getKeyThumbprint().isBlank()) {
            throw new ForbiddenException("Access token missing DPoP binding");
        }
        String expectedJkt = PushMfaKeyUtil.computeJwkThumbprint(publicKeyJwk);
        if (!Objects.equals(expectedJkt, confirmation.getKeyThumbprint())) {
            throw new ForbiddenException("Access token DPoP binding mismatch");
        }

        if (dpopLimits.requireAth() || parsedProof.ath() != null) {
            // `ath` is mainly enabled for RFC 9449 conformance. In this resource server, the
            // meaningful authorization decision still comes from possession of the enrolled key,
            // while the access token mostly contributes expiry/revocation/client attribution.
            // Still, once a client sends `ath`, validate it so an incorrect proof does not get
            // silently accepted when strict enforcement is disabled.
            String ath = PushMfaInputValidator.require(parsedProof.ath(), "ath");
            if (!Objects.equals(computeAccessTokenHash(accessTokenString), ath)) {
                throw new ForbiddenException("DPoP proof ath mismatch");
            }
        }

        if (!markDpopJtiUsed(realm().getId(), expectedJkt, parsedProof.jti())) {
            throw new ForbiddenException("DPoP proof replay detected");
        }
    }

    private static String computeAccessTokenHash(String accessTokenString) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(accessTokenString.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to compute access token hash", ex);
        }
    }

    private static final String DPOP_JTI_PREFIX = "push-mfa:dpop:jti:";

    private boolean markDpopJtiUsed(String realmId, String jkt, String jti) {
        SingleUseObjectProvider singleUse = session.singleUseObjects();
        if (singleUse == null) {
            throw new IllegalStateException("SingleUseObjectProvider unavailable");
        }
        String key = StorageKeyUtil.buildKey(DPOP_JTI_PREFIX, realmId, jkt, jti);
        return singleUse.putIfAbsent(key, dpopLimits.jtiTtlSeconds());
    }

    private UserModel getUser(String userId) {
        UserModel user = session.users().getUserById(realm(), userId);
        if (user == null) {
            throw new NotFoundException("User not found");
        }
        return user;
    }

    private static String extractClientId(AccessToken token) {
        Object clientId = token.getOtherClaims().get(OAuth2Constants.CLIENT_ID);
        return clientId instanceof String s ? s : token.getIssuedFor();
    }

    private static String jsonText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        return value.asText(null);
    }

    /**
     * Strips query and fragment parts from a URI string per RFC 9449 Section 4.2.
     *
     * <p>Both the server's request URI and the client-provided {@code htu} are normalized this way
     * so that old clients that include query parameters in {@code htu} remain compatible.
     */
    private static String stripQueryAndFragment(String uriString) {
        try {
            URI uri = new URI(uriString);
            return new URI(uri.getScheme(), uri.getAuthority(), uri.getPath(), null, null).toString();
        } catch (URISyntaxException ex) {
            return uriString;
        }
    }
}
