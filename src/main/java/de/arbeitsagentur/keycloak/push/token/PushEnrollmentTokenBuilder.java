package de.arbeitsagentur.keycloak.push.token;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
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
import org.keycloak.models.UserModel;
import org.keycloak.utils.StringUtil;

public final class PushEnrollmentTokenBuilder {

    private PushEnrollmentTokenBuilder() {}

    public static String build(
            KeycloakSession session, RealmModel realm, UserModel user, PushChallenge challenge, URI baseUri) {
        String signatureAlgorithm = realm.getDefaultSignatureAlgorithm();
        if (StringUtil.isBlank(signatureAlgorithm)) {
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
        payload.put("aud", realm.getName());
        payload.put("sub", user.getId());
        payload.put("username", user.getUsername());
        payload.put("realm", realm.getName());
        payload.put("enrollmentId", challenge.getId());
        payload.put("nonce", PushChallengeStore.encodeNonce(challenge.getNonce()));
        payload.put("exp", challenge.getExpiresAt().getEpochSecond());
        payload.put("iat", Instant.now().getEpochSecond());
        payload.put("typ", "push-enroll-challenge");

        String algorithmName = key.getAlgorithm() != null ? key.getAlgorithm() : signatureAlgorithm;
        Algorithm algorithm = resolveAlgorithm(algorithmName);

        PrivateKey privateKey = (PrivateKey) key.getPrivateKey();
        EncodingBuilder encodingBuilder =
                new JWSBuilder().kid(key.getKid()).type("JWT").jsonContent(payload);

        return encodingBuilder.sign(algorithm, privateKey);
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
