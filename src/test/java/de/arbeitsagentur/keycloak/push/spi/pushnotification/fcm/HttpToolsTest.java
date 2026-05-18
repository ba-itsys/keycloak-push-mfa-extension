package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.FcmPushMessage;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.FcmPushRequestBody;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.Notification;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.NotificationData;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class HttpToolsTest {
    @Mock
    private HttpClient mockHttpClient;

    @Mock
    private HttpResponse<String> mockHttpResponse;

    @Test
    public void testPostMessageRequest_Success() throws Exception {
        // Given
        Notification notification = new Notification("Test Title", "Test Body");
        NotificationData data = new NotificationData("another-token");
        FcmPushMessage message = new FcmPushMessage("token", notification, data);

        String url = "http://mock-fcm-url.com/message:send";
        String jwt = "jwt.token";

        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(200);

        // When
        HttpResponse<String> response =
                HttpTools.postMessageRequest(mockHttpClient, url, new FcmPushRequestBody(message), jwt);

        // Then
        verify(mockHttpClient).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        assertEquals(200, response.statusCode());
    }

    @Test
    public void testPostMessageRequest_Retry_Success() throws Exception {
        // Given
        Notification notification = new Notification("Test Title", "Test Body");
        NotificationData data = new NotificationData("another-token");
        FcmPushMessage message = new FcmPushMessage("token", notification, data);

        String url = "http://mock-fcm-url.com/message:send";
        String jwt = "jwt.token";

        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("Mocked IOException"))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(200);

        // When
        HttpResponse<String> response =
                HttpTools.postMessageRequest(mockHttpClient, url, new FcmPushRequestBody(message), jwt);

        // Then
        verify(mockHttpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        assertEquals(200, response.statusCode());
    }

    @Test
    public void testPostMessageRequest_Retry_Failure_Exception() throws Exception {
        // Given
        Notification notification = new Notification("Test Title", "Test Body");
        NotificationData data = new NotificationData("another-token");
        FcmPushMessage message = new FcmPushMessage("token", notification, data);

        String url = "http://mock-fcm-url.com/message:send";
        String jwt = "jwt.token";

        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("Mocked IOException"));

        // When
        assertThrows(IOException.class, () -> {
            HttpTools.postMessageRequest(mockHttpClient, url, new FcmPushRequestBody(message), jwt);
        });

        // Then
        verify(mockHttpClient, times(HttpTools.NUMBER_OF_RETRIES))
                .send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    public void testPostMessageRequest_Retry_Status_failure() throws Exception {
        // Given
        Notification notification = new Notification("Test Title", "Test Body");
        NotificationData data = new NotificationData("another-token");
        FcmPushMessage message = new FcmPushMessage("token", notification, data);

        String url = "http://mock-fcm-url.com/message:send";
        String jwt = "jwt.token";

        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(500);

        // When
        HttpResponse<String> response =
                HttpTools.postMessageRequest(mockHttpClient, url, new FcmPushRequestBody(message), jwt);

        // Then
        verify(mockHttpClient, times(HttpTools.NUMBER_OF_RETRIES))
                .send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        assertEquals(500, response.statusCode());
    }

    @Test
    public void testPostTokenRequest_Success() throws Exception {
        // Given
        String url = "http://mock-fcm-url.com/token:send";
        Map<String, String> formParams = new HashMap<>();
        formParams.put("grant_type", "client_credentials");
        formParams.put("client_id", "client-id");
        formParams.put("client_secret", "client-secret");

        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(200);

        // When
        HttpResponse<String> response = HttpTools.postTokenRequest(mockHttpClient, url, formParams);

        // Then
        verify(mockHttpClient).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        assertEquals(200, response.statusCode());
    }
}
