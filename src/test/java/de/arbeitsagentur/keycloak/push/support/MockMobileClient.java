package de.arbeitsagentur.keycloak.push.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
        return postJson("/enroll", enrollmentToken, null);
    }

    public Response approveLogin(String confirmToken) throws Exception {
        return postJson("/confirm-login", confirmToken, null);
    }

    private Response postJson(String path, String token, String context) throws Exception {
        var body = MAPPER.createObjectNode().put("token", token);
        if (context != null && !context.isBlank()) {
            body.put("context", context);
        }
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
