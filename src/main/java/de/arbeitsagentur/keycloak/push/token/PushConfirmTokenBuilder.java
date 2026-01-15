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
import org.keycloak.utils.StringUtil;

public final class PushConfirmTokenBuilder {

    private PushConfirmTokenBuilder() {}

    public static String build(
            KeycloakSession session,
            RealmModel realm,
            String credentialId,
            String challengeId,
            Instant challengeExpiresAt,
            URI baseUri) {
        return build(session, realm, credentialId, challengeId, challengeExpiresAt, baseUri, null);
    }

    public static String build(
            KeycloakSession session,
            RealmModel realm,
            String credentialId,
            String challengeId,
            Instant challengeExpiresAt,
            URI baseUri,
            String userVerification) {
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
        payload.put("credId", credentialId);
        payload.put("typ", PushMfaConstants.PUSH_MESSAGE_TYPE);
        payload.put("ver", PushMfaConstants.PUSH_MESSAGE_VERSION);
        payload.put("cid", challengeId);
        if (!StringUtil.isBlank(userVerification)) {
            payload.put("userVerification", userVerification);
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
