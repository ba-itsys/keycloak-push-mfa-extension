package de.arbeitsagentur.keycloak.push.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public final class MockMobileClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final URI baseUri;
    private final HttpClient http =
            HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();

    public MockMobileClient(URI baseUri) {
        this.baseUri = baseUri;
    }

    public Response enroll(String enrollmentToken) throws Exception {
        ObjectNode body = MAPPER.createObjectNode().put("token", enrollmentToken);
        return postJson("/enroll", body);
    }

    public Response approveLogin(String confirmToken) throws Exception {
        return approveLogin(confirmToken, null);
    }

    public Response approveLogin(String confirmToken, String userVerification) throws Exception {
        return respondLogin(confirmToken, "approve", userVerification);
    }

    public Response denyLogin(String confirmToken) throws Exception {
        return respondLogin(confirmToken, "deny", null);
    }

    private Response respondLogin(String confirmToken, String action, String userVerification) throws Exception {
        ObjectNode body = MAPPER.createObjectNode().put("token", confirmToken);
        if (action != null && !action.isBlank()) {
            body.put("action", action);
        }
        if (userVerification != null && !userVerification.isBlank()) {
            body.put("userVerification", userVerification);
        }
        return postJson("/confirm-login", body);
    }

    public Response enroll(String enrollmentToken, String context) throws Exception {
        ObjectNode body = MAPPER.createObjectNode().put("token", enrollmentToken);
        if (context != null && !context.isBlank()) {
            body.put("context", context);
        }
        return postJson("/enroll", body);
    }

    private Response postJson(String path, ObjectNode body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(baseUri.resolve(path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        JsonNode payload = parseOrNull(response.body());
        return new Response(response.statusCode(), payload);
    }

    private JsonNode parseOrNull(String body) {
        try {
            return MAPPER.readTree(body);
        } catch (Exception ignored) {
            return null;
        }
    }

    public record Response(int httpStatus, JsonNode payload) {
        public int responseStatus() {
            if (payload == null) {
                return httpStatus;
            }
            if (payload.has("responseStatus")) {
                return payload.path("responseStatus").asInt(httpStatus);
            }
            if (payload.has("status")) {
                return payload.path("status").asInt(httpStatus);
            }
            return httpStatus;
        }

        public String error() {
            if (payload == null) {
                return null;
            }
            String message = payload.path("error").asText(null);
            return (message == null || message.isBlank()) ? null : message;
        }
    }
}
