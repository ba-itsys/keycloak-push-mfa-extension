package de.arbeitsagentur.keycloak.push.token;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSBuilder.EncodingBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

public final class PushConfirmTokenBuilder {

    private PushConfirmTokenBuilder() {}

    public static String build(
            KeycloakSession session,
            RealmModel realm,
            String credentialId,
            String challengeId,
            Instant challengeExpiresAt,
            URI baseUri,
            String clientId,
            String clientDisplayName) {
        String signatureAlgorithm = realm.getDefaultSignatureAlgorithm();
        if (signatureAlgorithm == null || signatureAlgorithm.isBlank()) {
            signatureAlgorithm = Algorithm.RS256.toString();
        }
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, signatureAlgorithm);
        if (key == null || key.getPrivateKey() == null) {
            throw new IllegalStateException("No active signing key for realm");
        }

        URI issuer =
                UriBuilder.fromUri(baseUri).path("realms").path(realm.getName()).build();

        Map<String, Object> payload = new HashMap<>();
        payload.put("iss", issuer.toString());
        payload.put("credId", credentialId);
        payload.put("typ", PushMfaConstants.PUSH_MESSAGE_TYPE);
        payload.put("ver", PushMfaConstants.PUSH_MESSAGE_VERSION);
        payload.put("cid", challengeId);
        if (clientId != null) {
            payload.put("client_id", clientId);
        }
        if (clientDisplayName != null && !clientDisplayName.isBlank()) {
            payload.put("client_name", clientDisplayName);
        }
        Instant issuedAt = Instant.now();
        payload.put("iat", issuedAt.getEpochSecond());
        payload.put("exp", challengeExpiresAt.getEpochSecond());

        String algorithmName = key.getAlgorithm() != null ? key.getAlgorithm() : signatureAlgorithm;
        Algorithm algorithm = resolveAlgorithm(algorithmName);

        PrivateKey privateKey = (PrivateKey) key.getPrivateKey();
        EncodingBuilder builder = new JWSBuilder().kid(key.getKid()).type("JWT").jsonContent(payload);

        return builder.sign(algorithm, privateKey);
    }

    private static Algorithm resolveAlgorithm(String name) {
        if (name != null) {
            for (Algorithm candidate : Algorithm.values()) {
                if (candidate.toString().equalsIgnoreCase(name)) {
                    return candidate;
                }
            }
        }
        return Algorithm.RS256;
    }
}
