package de.arbeitsagentur.keycloak.push.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

public final class AdminClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String PUSH_FLOW_ALIAS = "browser-push-forms";
    private static final String PUSH_AUTHENTICATOR_ID = "push-mfa-authenticator";

    private final URI baseUri;
    private final HttpClient http =
            HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    private String accessToken;

    public AdminClient(URI baseUri) {
        this.baseUri = baseUri;
    }

    public String ensureUser(String username, String password) throws Exception {
        ensureAccessToken();
        String userId = findUserId(username);
        if (userId == null) {
            userId = createUser(username);
        }
        if (password != null && !password.isBlank()) {
            setUserPassword(userId, password);
        }
        return userId;
    }

    public JsonNode fetchPushCredential(String userId) throws Exception {
        JsonNode items = readCredentials(userId);
        for (JsonNode item : items) {
            if ("push-mfa".equals(item.path("type").asText())) {
                String credentialData = item.path("credentialData").asText();
                return MAPPER.readTree(credentialData);
            }
        }
        throw new IllegalStateException("Push credential not found for user " + userId);
    }

    public void resetUserState(String username) throws Exception {
        String userId = findUserId(username);
        if (userId == null || userId.isBlank()) {
            throw new IllegalStateException("User not found: " + username);
        }
        deletePushCredentials(userId);
        logoutUser(userId);
        clearRealmCaches();
    }

    public void configurePushMfaUserVerification(String mode) throws Exception {
        configurePushMfaUserVerification(mode, null);
    }

    public void configurePushMfaUserVerification(String mode, Integer pinLength) throws Exception {
        ensureAccessToken();
        String normalizedMode = mode == null || mode.isBlank() ? "none" : mode.trim();
        JsonNode execution = findExecution(PUSH_FLOW_ALIAS, PUSH_AUTHENTICATOR_ID);
        if (execution == null) {
            throw new IllegalStateException("Push MFA authenticator execution not found in flow " + PUSH_FLOW_ALIAS);
        }
        String executionId = execution.path("id").asText(null);
        if (executionId == null || executionId.isBlank()) {
            throw new IllegalStateException("Push MFA authenticator execution id missing");
        }

        String configId = execution.path("authenticationConfig").asText(null);
        if (configId == null || configId.isBlank()) {
            configId = execution.path("authenticatorConfig").asText(null);
        }
        if (configId != null && configId.isBlank()) {
            configId = null;
        }

        if (configId == null) {
            URI createConfigUri =
                    baseUri.resolve("/admin/realms/demo/authentication/executions/" + executionId + "/config");
            ObjectNode configNode = MAPPER.createObjectNode();
            configNode.put("userVerification", normalizedMode);
            if (pinLength != null) {
                configNode.put("userVerificationPinLength", String.valueOf(pinLength));
            }
            ObjectNode payload = MAPPER.createObjectNode();
            payload.put("alias", "push-mfa-authenticator-config");
            payload.set("config", configNode);
            HttpResponse<String> response = http.send(
                    HttpRequest.newBuilder(createConfigUri)
                            .header("Authorization", "Bearer " + accessToken)
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(payload.toString()))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 201) {
                throw new IllegalStateException(
                        "Failed to create authenticator config: " + response.statusCode() + " body=" + response.body());
            }
        } else {
            URI configUri = baseUri.resolve("/admin/realms/demo/authentication/config/" + configId);
            HttpResponse<String> existingResponse = http.send(
                    HttpRequest.newBuilder(configUri)
                            .header("Authorization", "Bearer " + accessToken)
                            .header("Accept", "application/json")
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            if (existingResponse.statusCode() != 200) {
                throw new IllegalStateException("Failed to read authenticator config: " + existingResponse.statusCode()
                        + " body=" + existingResponse.body());
            }
            JsonNode existing = MAPPER.readTree(existingResponse.body());
            String alias = existing.path("alias").asText("push-mfa-authenticator-config");
            ObjectNode configNode = MAPPER.createObjectNode();
            JsonNode existingConfig = existing.path("config");
            if (existingConfig.isObject()) {
                existingConfig.fields().forEachRemaining(entry -> configNode.set(entry.getKey(), entry.getValue()));
            }
            configNode.put("userVerification", normalizedMode);
            if (pinLength != null) {
                configNode.put("userVerificationPinLength", String.valueOf(pinLength));
            }
            ObjectNode payload = MAPPER.createObjectNode();
            payload.put("id", configId);
            payload.put("alias", alias);
            payload.set("config", configNode);

            HttpResponse<String> updateResponse = http.send(
                    HttpRequest.newBuilder(configUri)
                            .header("Authorization", "Bearer " + accessToken)
                            .header("Content-Type", "application/json")
                            .PUT(HttpRequest.BodyPublishers.ofString(payload.toString()))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            if (updateResponse.statusCode() != 204) {
                throw new IllegalStateException("Failed to update authenticator config: " + updateResponse.statusCode()
                        + " body=" + updateResponse.body());
            }
        }

        clearRealmCaches();
    }

    private String createUser(String username) throws Exception {
        URI createUri = baseUri.resolve("/admin/realms/demo/users");
        String payload = MAPPER.createObjectNode()
                .put("username", username)
                .put("enabled", true)
                .toString();
        HttpRequest request = HttpRequest.newBuilder(createUri)
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 201) {
            String location = response.headers()
                    .firstValue("Location")
                    .orElseThrow(() -> new IllegalStateException("Missing Location header"));
            int idx = location.lastIndexOf('/');
            if (idx == -1 || idx == location.length() - 1) {
                throw new IllegalStateException("Unexpected user location: " + location);
            }
            return location.substring(idx + 1);
        }
        assertEquals(409, response.statusCode(), () -> "User create failed: " + response.body());
        String userId = findUserId(username);
        if (userId == null) {
            throw new IllegalStateException("User lookup failed after create conflict: " + username);
        }
        return userId;
    }

    private void setUserPassword(String userId, String password) throws Exception {
        URI resetUri = baseUri.resolve("/admin/realms/demo/users/" + userId + "/reset-password");
        String payload = MAPPER.createObjectNode()
                .put("type", "password")
                .put("value", password)
                .put("temporary", false)
                .toString();
        HttpRequest request = HttpRequest.newBuilder(resetUri)
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(payload))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(204, response.statusCode(), () -> "Password set failed: " + response.body());
    }

    private void deletePushCredentials(String userId) throws Exception {
        JsonNode credentials = readCredentials(userId);
        for (JsonNode item : credentials) {
            if (!"push-mfa".equals(item.path("type").asText())) {
                continue;
            }
            String credentialId = item.path("id").asText(null);
            if (credentialId == null || credentialId.isBlank()) {
                continue;
            }
            URI deleteUri = baseUri.resolve("/admin/realms/demo/users/" + userId + "/credentials/" + credentialId);
            HttpRequest deleteRequest = HttpRequest.newBuilder(deleteUri)
                    .header("Authorization", "Bearer " + accessToken)
                    .DELETE()
                    .build();
            HttpResponse<String> deleteResponse = http.send(deleteRequest, HttpResponse.BodyHandlers.ofString());
            assertEquals(204, deleteResponse.statusCode(), () -> "Credential delete failed: " + deleteResponse.body());
        }
    }

    private void logoutUser(String userId) throws Exception {
        URI logoutUri = baseUri.resolve("/admin/realms/demo/users/" + userId + "/logout");
        HttpRequest request = HttpRequest.newBuilder(logoutUri)
                .header("Authorization", "Bearer " + accessToken)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(204, response.statusCode(), () -> "Logout failed: " + response.body());
    }

    private void clearRealmCaches() throws Exception {
        URI clearRealmCache = baseUri.resolve("/admin/realms/demo/clear-realm-cache");
        HttpRequest realmCacheRequest = HttpRequest.newBuilder(clearRealmCache)
                .header("Authorization", "Bearer " + accessToken)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> realmResponse = http.send(realmCacheRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(204, realmResponse.statusCode(), () -> "Realm cache clear failed: " + realmResponse.body());

        URI clearUserCache = baseUri.resolve("/admin/realms/demo/clear-user-cache");
        HttpRequest userCacheRequest = HttpRequest.newBuilder(clearUserCache)
                .header("Authorization", "Bearer " + accessToken)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> userResponse = http.send(userCacheRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(204, userResponse.statusCode(), () -> "User cache clear failed: " + userResponse.body());
    }

    private JsonNode readCredentials(String userId) throws Exception {
        ensureAccessToken();
        URI credentialsUri = baseUri.resolve("/admin/realms/demo/users/" + userId + "/credentials");
        HttpRequest request = HttpRequest.newBuilder(credentialsUri)
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "Credential fetch failed: " + response.body());
        JsonNode items = MAPPER.readTree(response.body());
        if (!items.isArray()) {
            throw new IllegalStateException("Unexpected credential response: " + response.body());
        }
        return items;
    }

    private JsonNode findExecution(String flowAlias, String authenticator) throws Exception {
        URI uri = baseUri.resolve("/admin/realms/demo/authentication/flows/" + flowAlias + "/executions");
        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(uri)
                        .header("Authorization", "Bearer " + accessToken)
                        .header("Accept", "application/json")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException(
                    "Failed to read flow executions: " + response.statusCode() + " body=" + response.body());
        }
        JsonNode executions = MAPPER.readTree(response.body());
        if (!executions.isArray()) {
            throw new IllegalStateException("Unexpected flow executions response: " + response.body());
        }
        for (JsonNode execution : executions) {
            String authenticatorId = execution.path("authenticator").asText(null);
            String providerId = execution.path("providerId").asText(null);
            if (authenticator.equals(authenticatorId) || authenticator.equals(providerId)) {
                return execution;
            }
        }
        return null;
    }

    private String findUserId(String username) throws Exception {
        ensureAccessToken();
        URI usersUri = baseUri.resolve("/admin/realms/demo/users?username=" + urlEncode(username));
        HttpRequest request = HttpRequest.newBuilder(usersUri)
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "User lookup failed: " + response.body());
        JsonNode users = MAPPER.readTree(response.body());
        if (users.isArray() && !users.isEmpty()) {
            return users.get(0).path("id").asText(null);
        }
        return null;
    }

    private void ensureAccessToken() throws Exception {
        if (accessToken != null && !accessToken.isBlank()) {
            return;
        }
        URI tokenUri = baseUri.resolve("/realms/master/protocol/openid-connect/token");
        String body = "grant_type=password&client_id=admin-cli&username=admin&password=admin";
        HttpRequest request = HttpRequest.newBuilder(tokenUri)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "Admin token request failed: " + response.body());
        JsonNode json = MAPPER.readTree(response.body());
        accessToken = json.path("access_token").asText();
        assertNotNull(accessToken);
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
