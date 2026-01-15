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

package de.arbeitsagentur.keycloak.push.util;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.BadRequestException;
import java.security.MessageDigest;
import java.util.Base64;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

public final class PushMfaKeyUtil {

    private PushMfaKeyUtil() {}

    public static void requireSupportedAlgorithm(Algorithm algorithm, String context) {
        if (algorithm == null || !isSupportedAlgorithmName(algorithm.name())) {
            throw new BadRequestException("Unsupported " + context + " algorithm: " + algorithm);
        }
    }

    public static void requireSupportedAlgorithm(String algName, String context) {
        if (!isSupportedAlgorithmName(algName)) {
            throw new BadRequestException("Unsupported " + context + " algorithm: " + algName);
        }
    }

    public static String requireAlgorithmFromJwk(JsonNode jwkNode, String context) {
        if (jwkNode == null) {
            throw new BadRequestException("JWK missing alg");
        }
        JsonNode algNode = jwkNode.get("alg");
        if (algNode == null || !algNode.isTextual() || StringUtil.isBlank(algNode.asText())) {
            throw new BadRequestException("JWK missing alg");
        }
        String algorithm = algNode.asText();
        requireSupportedAlgorithm(algorithm, context);
        return algorithm.toUpperCase();
    }

    public static KeyWrapper keyWrapperFromNode(JsonNode jwkNode) {
        if (jwkNode == null) {
            throw new BadRequestException("JWK is required");
        }
        try {
            JWK jwk = JsonSerialization.mapper.treeToValue(jwkNode, JWK.class);
            KeyWrapper wrapper = JWKSUtils.getKeyWrapper(jwk);
            if (wrapper == null) {
                throw new BadRequestException("Unsupported JWK");
            }
            if (wrapper.getAlgorithm() == null && jwk.getAlgorithm() != null) {
                wrapper.setAlgorithm(jwk.getAlgorithm());
            }
            return wrapper;
        } catch (BadRequestException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new BadRequestException("Unable to parse JWK", ex);
        }
    }

    public static KeyWrapper keyWrapperFromString(String jwkJson) {
        if (StringUtil.isBlank(jwkJson)) {
            throw new BadRequestException("Stored credential missing JWK");
        }
        try {
            JsonNode node = JsonSerialization.mapper.readTree(jwkJson);
            return keyWrapperFromNode(node);
        } catch (BadRequestException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new BadRequestException("Stored credential contains invalid JWK", ex);
        }
    }

    public static void ensureKeyMatchesAlgorithm(KeyWrapper keyWrapper, String algorithm) {
        if (keyWrapper == null) {
            throw new BadRequestException("JWK is required");
        }
        if (StringUtil.isBlank(algorithm)) {
            throw new BadRequestException("Missing algorithm");
        }

        String normalizedAlg = algorithm.toUpperCase();
        if (keyWrapper.getAlgorithm() != null && !normalizedAlg.equalsIgnoreCase(keyWrapper.getAlgorithm())) {
            throw new BadRequestException("JWK algorithm mismatch");
        }
        if (KeyType.RSA.equals(keyWrapper.getType())) {
            if (!normalizedAlg.startsWith("RS")) {
                throw new BadRequestException("RSA keys require RS* algorithms");
            }
        } else if (KeyType.EC.equals(keyWrapper.getType())) {
            if (!normalizedAlg.startsWith("ES")) {
                throw new BadRequestException("EC keys require ES* algorithms");
            }
            String curve = keyWrapper.getCurve();
            String expectedCurve = curveForAlgorithm(normalizedAlg);
            if (curve != null && expectedCurve != null && !expectedCurve.equalsIgnoreCase(curve)) {
                throw new BadRequestException("EC curve " + curve + " incompatible with " + normalizedAlg);
            }
        } else {
            throw new BadRequestException("Unsupported key type: " + keyWrapper.getType());
        }
        keyWrapper.setAlgorithm(normalizedAlg);
    }

    public static String computeJwkThumbprint(String jwkJson) {
        try {
            JsonNode jwk = JsonSerialization.mapper.readTree(jwkJson);
            String kty = PushMfaInputValidator.require(jwk.path("kty").asText(null), "kty");
            var canonical = JsonSerialization.mapper.createObjectNode();
            if ("RSA".equalsIgnoreCase(kty)) {
                String n = PushMfaInputValidator.require(jwk.path("n").asText(null), "n");
                String e = PushMfaInputValidator.require(jwk.path("e").asText(null), "e");
                canonical.put("e", e);
                canonical.put("kty", "RSA");
                canonical.put("n", n);
            } else if ("EC".equalsIgnoreCase(kty)) {
                String crv = PushMfaInputValidator.require(jwk.path("crv").asText(null), "crv");
                String x = PushMfaInputValidator.require(jwk.path("x").asText(null), "x");
                String y = PushMfaInputValidator.require(jwk.path("y").asText(null), "y");
                canonical.put("crv", crv);
                canonical.put("kty", "EC");
                canonical.put("x", x);
                canonical.put("y", y);
            } else {
                throw new BadRequestException("Unsupported key type for DPoP binding");
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(JsonSerialization.mapper.writeValueAsBytes(canonical));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (BadRequestException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new BadRequestException("Unable to compute JWK thumbprint", ex);
        }
    }

    private static boolean isSupportedAlgorithmName(String algName) {
        if (StringUtil.isBlank(algName)) {
            return false;
        }
        String normalized = algName.toUpperCase();
        return normalized.startsWith("RS") || normalized.startsWith("ES");
    }

    private static String curveForAlgorithm(String algorithm) {
        return switch (algorithm) {
            case "ES256" -> "P-256";
            case "ES384" -> "P-384";
            case "ES512" -> "P-521";
            default -> null;
        };
    }
}
