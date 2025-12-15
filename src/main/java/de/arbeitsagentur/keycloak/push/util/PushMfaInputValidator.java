package de.arbeitsagentur.keycloak.push.util;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.BadRequestException;
import java.util.List;
import java.util.UUID;
import org.keycloak.utils.StringUtil;

public final class PushMfaInputValidator {

    private static final List<String> FORBIDDEN_PRIVATE_JWK_FIELDS =
            List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k");

    private PushMfaInputValidator() {}

    public static String require(String value, String fieldName) {
        if (StringUtil.isBlank(value)) {
            throw new BadRequestException("Missing field: " + fieldName);
        }
        return value;
    }

    public static void requireMaxLength(String value, int maxLength, String fieldName) {
        if (value == null) {
            return;
        }
        if (value.length() > maxLength) {
            throw new BadRequestException("Field too long: " + fieldName);
        }
    }

    public static String requireBoundedText(String value, int maxLength, String fieldName) {
        String normalized = require(value, fieldName);
        requireMaxLength(normalized, maxLength, fieldName);
        requireNoControlCharacters(normalized, fieldName);
        return normalized;
    }

    public static String optionalBoundedText(String value, int maxLength, String fieldName) {
        if (value == null) {
            return null;
        }
        requireMaxLength(value, maxLength, fieldName);
        requireNoControlCharacters(value, fieldName);
        return value;
    }

    public static String requireUuid(String value, String fieldName) {
        String normalized = require(value, fieldName);
        requireNoControlCharacters(normalized, fieldName);
        if (normalized.length() != 36) {
            throw new BadRequestException("Invalid UUID field: " + fieldName);
        }
        try {
            UUID.fromString(normalized);
        } catch (IllegalArgumentException ex) {
            throw new BadRequestException("Invalid UUID field: " + fieldName);
        }
        return normalized;
    }

    public static void ensurePublicJwk(JsonNode jwkNode, String fieldName) {
        if (jwkNode == null || jwkNode.isNull() || jwkNode.isMissingNode()) {
            throw new BadRequestException("Missing field: " + fieldName);
        }
        if (!jwkNode.isObject()) {
            throw new BadRequestException("JWK must be an object");
        }
        for (String forbidden : FORBIDDEN_PRIVATE_JWK_FIELDS) {
            JsonNode value = jwkNode.get(forbidden);
            if (value != null && !value.isNull()) {
                throw new BadRequestException("JWK must not contain private key parameters");
            }
        }
    }

    private static void requireNoControlCharacters(String value, String fieldName) {
        if (value == null) {
            return;
        }
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) {
                throw new BadRequestException("Invalid characters in field: " + fieldName);
            }
        }
    }
}
