package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.FcmPushRequestBody;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import org.jboss.logging.Logger;

public class HttpTools {

    private static final Logger LOG = Logger.getLogger(HttpTools.class);

    public static final int NUMBER_OF_RETRIES = 3;
    private static final Duration INITIAL_DELAY = Duration.ofSeconds(1);

    private HttpTools() {
        // Prevent instantiation of utility class
    }

    public static HttpResponse<String> postMessageRequest(
            HttpClient client, String url, FcmPushRequestBody requestBody, String jwt)
            throws IOException, InterruptedException {
        ObjectMapper objectMapper = new ObjectMapper();
        String json = objectMapper.writeValueAsString(requestBody);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        return postWithRetry(client, request);
    }

    public static HttpResponse<String> postTokenRequest(HttpClient client, String url, Map<String, String> formParams)
            throws IOException, InterruptedException {
        String formString = formParams.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .reduce("", (a, b) -> a + "&" + b)
                .substring(1);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED)
                .POST(HttpRequest.BodyPublishers.ofString(formString))
                .build();

        return postWithRetry(client, request);
    }

    private static HttpResponse<String> postWithRetry(HttpClient client, HttpRequest request)
            throws IOException, InterruptedException {
        Duration delay = INITIAL_DELAY;
        for (int attempt = 1; attempt <= NUMBER_OF_RETRIES; attempt++) {
            try {
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                if ((response.statusCode() == 200) || (attempt == NUMBER_OF_RETRIES)) {
                    return response; // Return response if successful or if it's the last attempt
                }
            } catch (IOException e) {
                LOG.warn(e);
            }
            Thread.sleep(delay.toMillis());
            delay = delay.multipliedBy(2); // Exponential backoff
        }
        throw new IOException("Failed to complete request after " + NUMBER_OF_RETRIES + " retries");
    }
}
