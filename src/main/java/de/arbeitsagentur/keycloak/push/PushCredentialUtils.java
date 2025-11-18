package de.arbeitsagentur.keycloak.push;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public final class PushCredentialUtils {

    private PushCredentialUtils() {
    }

    private static ObjectMapper mapper() {
        return JsonSerialization.mapper;
    }

    public static String toJson(PushCredentialData data) {
        try {
            return mapper().writeValueAsString(data);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Unable to serialize push credential data", ex);
        }
    }

    public static PushCredentialData fromJson(String json) {
        try {
            return mapper().readValue(json, PushCredentialData.class);
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to deserialize push credential data", ex);
        }
    }
}
