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
import java.time.Instant;
import java.util.List;
import java.util.Objects;
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

    public record DeviceAssertion(UserModel user, CredentialModel credential, PushCredentialData credentialData) {}

    public DeviceAssertion authenticate(HttpHeaders headers, UriInfo uriInfo, String httpMethod) {
        AuthContext ctx = new AuthContext(httpMethod, uriInfo.getPath());

        try {
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

            String tokenSubject = PushMfaInputValidator.requireBoundedText(
                    jsonText(payload, "sub"), inputLimits.maxUserIdLength(), "sub");
            String tokenDeviceId = PushMfaInputValidator.requireBoundedText(
                    jsonText(payload, "deviceId"), inputLimits.maxDeviceIdLength(), "deviceId");

            ctx.userId = tokenSubject;

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

            ctx.credentialId = credentialData.getCredentialId();

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
        String credentialId;

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
                        ctx.credentialId,
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
