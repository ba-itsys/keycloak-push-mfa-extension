package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.FcmPushRequestBody;
import jakarta.ws.rs.core.HttpHeaders;
import java.io.IOException;
import java.util.List;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;

public class HttpTools {

    private HttpTools() {
        // Prevent instantiation of utility class
    }

    public static HttpResult postMessageRequest(String url, FcmPushRequestBody requestBody, String jwt)
            throws IOException, InterruptedException {
        ObjectMapper objectMapper = new ObjectMapper();
        String json = objectMapper.writeValueAsString(requestBody);

        HttpPost request = new HttpPost(url);
        request.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + jwt);
        request.setHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType());
        request.setEntity(new StringEntity(json));

        try (CloseableHttpClient client = HttpClientFactory.getHttpClient()) {
            return client.execute(request, new HttpResponseHandler());
        }
    }

    public static HttpResult postTokenRequest(String url, List<NameValuePair> formParams)
            throws IOException, InterruptedException {

        HttpPost request = new HttpPost(url);
        request.setHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.getMimeType());
        request.setEntity(new UrlEncodedFormEntity(formParams));

        try (CloseableHttpClient client = HttpClientFactory.getHttpClient()) {
            return client.execute(request, new HttpResponseHandler());
        }
    }
}
