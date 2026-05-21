package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.FcmPushMessage;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.FcmPushRequestBody;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.Notification;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.NotificationData;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util.HttpClientFactory;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util.HttpResponseHandler;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util.HttpResult;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util.HttpTools;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class HttpToolsTest {
    @Mock
    private CloseableHttpClient mockHttpClient;

    @Mock
    private HttpResponse mockHttpResponse;

    @Mock
    private StatusLine mockStatusLine;

    @Mock
    private HttpEntity mockHttpEntity;

    @Test
    public void testPostMessageRequest_Success() throws Exception {
        // Given
        Notification notification = new Notification("Test Title", "Test Body");
        NotificationData data = new NotificationData("another-token");
        FcmPushMessage message = new FcmPushMessage("token", notification, data);

        String url = "http://mock-fcm-url.com/message:send";
        String jwt = "jwt.token";

        when(mockHttpClient.execute(any(HttpUriRequest.class), any(ResponseHandler.class)))
                .thenAnswer((InvocationOnMock invocation) -> {
                    return new HttpResponseHandler().handleResponse(mockHttpResponse);
                });
        when(mockHttpResponse.getStatusLine()).thenReturn(mockStatusLine);
        when(mockStatusLine.getStatusCode()).thenReturn(200);
        when(mockHttpResponse.getEntity()).thenReturn(mockHttpEntity);
        when(mockHttpEntity.getContent()).thenReturn(new java.io.ByteArrayInputStream("{}".getBytes()));

        try (MockedStatic<HttpClientFactory> mockedFactory = mockStatic(HttpClientFactory.class)) {
            mockedFactory.when(HttpClientFactory::getHttpClient).thenReturn(mockHttpClient);

            // When
            HttpResult response = HttpTools.postMessageRequest(url, new FcmPushRequestBody(message), jwt);

            // Then
            verify(mockHttpClient).execute(any(HttpUriRequest.class), any(ResponseHandler.class));
            assertEquals(200, response.statusCode());
        }
    }

    @Test
    public void testPostMessageRequest_Error() throws Exception {
        // Given
        Notification notification = new Notification("Test Title", "Test Body");
        NotificationData data = new NotificationData("another-token");
        FcmPushMessage message = new FcmPushMessage("token", notification, data);

        String url = "http://mock-fcm-url.com/message:send";
        String jwt = "jwt.token";

        when(mockHttpClient.execute(any(HttpUriRequest.class), any(ResponseHandler.class)))
                .thenAnswer((InvocationOnMock invocation) -> {
                    return new HttpResponseHandler().handleResponse(mockHttpResponse);
                });
        when(mockHttpResponse.getStatusLine()).thenReturn(mockStatusLine);
        when(mockStatusLine.getStatusCode()).thenReturn(500);
        when(mockHttpResponse.getEntity()).thenReturn(mockHttpEntity);
        when(mockHttpEntity.getContent()).thenReturn(new java.io.ByteArrayInputStream("Server Error".getBytes()));

        try (MockedStatic<HttpClientFactory> mockedFactory = mockStatic(HttpClientFactory.class)) {
            mockedFactory.when(HttpClientFactory::getHttpClient).thenReturn(mockHttpClient);

            // When
            HttpResult response = HttpTools.postMessageRequest(url, new FcmPushRequestBody(message), jwt);

            // Then
            verify(mockHttpClient).execute(any(HttpUriRequest.class), any(ResponseHandler.class));
            assertEquals(500, response.statusCode());
            assertEquals("Server Error", response.body());
        }
    }

    @Test
    public void testPostMessageRequest_IOException() throws Exception {
        // Given
        Notification notification = new Notification("Test Title", "Test Body");
        NotificationData data = new NotificationData("another-token");
        FcmPushMessage message = new FcmPushMessage("token", notification, data);

        String url = "http://mock-fcm-url.com/message:send";
        String jwt = "jwt.token";

        when(mockHttpClient.execute(any(HttpUriRequest.class), any(ResponseHandler.class)))
                .thenThrow(new IOException("Mocked IOException"));

        try (MockedStatic<HttpClientFactory> mockedFactory = mockStatic(HttpClientFactory.class)) {
            mockedFactory.when(HttpClientFactory::getHttpClient).thenReturn(mockHttpClient);
            // When
            IOException thrown = assertThrows(IOException.class, () -> {
                HttpTools.postMessageRequest(url, new FcmPushRequestBody(message), jwt);
            });

            // Then
            verify(mockHttpClient).execute(any(HttpUriRequest.class), any(ResponseHandler.class));
            assertEquals("Mocked IOException", thrown.getMessage());
        }
    }

    @Test
    public void testPostTokenRequest_Success() throws Exception {
        // Given
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"));
        params.add(new BasicNameValuePair("assertion", "jwt-token"));

        String url = "http://mock-fcm-url.com/token";
        String responseJson =
                "{\n  \"access_token\": \"mocked-access-token\",\n  \"token_type\": \"Bearer\",\n  \"expires_in\": 3600\n}";

        when(mockHttpClient.execute(any(HttpUriRequest.class), any(ResponseHandler.class)))
                .thenAnswer((InvocationOnMock invocation) -> {
                    return new HttpResponseHandler().handleResponse(mockHttpResponse);
                });
        when(mockHttpResponse.getStatusLine()).thenReturn(mockStatusLine);
        when(mockStatusLine.getStatusCode()).thenReturn(200);
        when(mockHttpResponse.getEntity()).thenReturn(mockHttpEntity);
        when(mockHttpEntity.getContent()).thenReturn(new java.io.ByteArrayInputStream(responseJson.getBytes()));

        try (MockedStatic<HttpClientFactory> mockedFactory = mockStatic(HttpClientFactory.class)) {
            mockedFactory.when(HttpClientFactory::getHttpClient).thenReturn(mockHttpClient);

            // When
            HttpResult response = HttpTools.postTokenRequest(url, params);

            // Then
            verify(mockHttpClient).execute(any(HttpUriRequest.class), any(ResponseHandler.class));
            assertEquals(200, response.statusCode());
            assertEquals(responseJson, response.body());
        }
    }

    @Test
    public void testPostTokenRequest_Error() throws Exception {
        // Given
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"));
        params.add(new BasicNameValuePair("assertion", "jwt-token"));

        String url = "http://mock-fcm-url.com/token";
        String responseJson = "Client Error";

        when(mockHttpClient.execute(any(HttpUriRequest.class), any(ResponseHandler.class)))
                .thenAnswer((InvocationOnMock invocation) -> {
                    return new HttpResponseHandler().handleResponse(mockHttpResponse);
                });
        when(mockHttpResponse.getStatusLine()).thenReturn(mockStatusLine);
        when(mockStatusLine.getStatusCode()).thenReturn(400);
        when(mockHttpResponse.getEntity()).thenReturn(mockHttpEntity);
        when(mockHttpEntity.getContent()).thenReturn(new java.io.ByteArrayInputStream(responseJson.getBytes()));

        try (MockedStatic<HttpClientFactory> mockedFactory = mockStatic(HttpClientFactory.class)) {
            mockedFactory.when(HttpClientFactory::getHttpClient).thenReturn(mockHttpClient);

            // When
            HttpResult response = HttpTools.postTokenRequest(url, params);

            // Then
            verify(mockHttpClient).execute(any(HttpUriRequest.class), any(ResponseHandler.class));
            assertEquals(400, response.statusCode());
            assertEquals(responseJson, response.body());
        }
    }

    @Test
    public void testPostTokenRequest_IOException() throws Exception {
        // Given
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"));
        params.add(new BasicNameValuePair("assertion", "jwt-token"));

        String url = "http://mock-fcm-url.com/token";

        when(mockHttpClient.execute(any(HttpUriRequest.class), any(ResponseHandler.class)))
                .thenThrow(new IOException("error"));

        try (MockedStatic<HttpClientFactory> mockedFactory = mockStatic(HttpClientFactory.class)) {
            mockedFactory.when(HttpClientFactory::getHttpClient).thenReturn(mockHttpClient);

            // When
            IOException thrown = assertThrows(IOException.class, () -> {
                HttpTools.postTokenRequest(url, params);
            });

            // Then
            verify(mockHttpClient).execute(any(HttpUriRequest.class), any(ResponseHandler.class));
            assertEquals("error", thrown.getMessage());
        }
    }
}
