package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.Proxy;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class HttpClientFactoryTest {
    @Mock
    private RealmModel realm;

    @AfterEach
    void cleanUp() {
        try {
            Field clientField = HttpClientFactory.class.getDeclaredField("singletonInstance");
            clientField.setAccessible(true);
            clientField.set(null, null);
        } catch (Exception e) {
            // Ignore exceptions during cleanup
        }
        Mockito.reset(realm);
    }

    @Test
    public void shouldCreateHttpClientWithoutProxy() {
        // Given
        when(realm.getAttribute("httpProxyEnabled")).thenReturn(null);

        // When
        HttpClient client = HttpClientFactory.getHttpClient(realm);

        // Then
        assertNotNull(client);
        assertTrue(client.proxy().isEmpty());
    }

    @Test
    public void shouldCreateHttpClientWithProxy() throws Exception {
        // Given
        when(realm.getAttribute("httpProxyEnabled")).thenReturn("True");
        when(realm.getAttribute("httpProxyHost")).thenReturn("web.proxy.svc.cluster.local");
        when(realm.getAttribute("httpProxyPort")).thenReturn("8081");

        // When
        HttpClient client = HttpClientFactory.getHttpClient(realm);

        // Then
        assertNotNull(client);
        assertTrue(client.proxy().isPresent());
        List<Proxy> proxies = client.proxy().get().select(new URI("http://test.com/messages:send"));
        assertTrue(proxies.getFirst().address().toString().contains("web.proxy.svc.cluster.local"));
        assertTrue(proxies.getFirst().address().toString().contains(":8081"));
    }

    @Test
    public void shouldCreateHttpClientOnlyOnce() {
        // Given
        when(realm.getAttribute("httpProxyEnabled")).thenReturn(null);

        // When
        HttpClient client1 = HttpClientFactory.getHttpClient(realm);
        HttpClient client2 = HttpClientFactory.getHttpClient(realm);

        // Then
        assertNotNull(client1);
        assertNotNull(client2);
        assertEquals(client1, client2);
    }

    @Test
    public void shouldCreateHttpClientWithoutProxyAtMissingHost() {
        // Given
        when(realm.getAttribute("httpProxyEnabled")).thenReturn("true");
        when(realm.getAttribute("httpProxyHost")).thenReturn(null);
        when(realm.getAttribute("httpProxyPort")).thenReturn("8081");

        // When
        HttpClient client = HttpClientFactory.getHttpClient(realm);

        // Then
        assertNotNull(client);
        assertTrue(client.proxy().isEmpty());
    }

    @Test
    public void shouldCreateHttpClientWithoutProxyAtMissingPort() {
        // Given
        when(realm.getAttribute("httpProxyEnabled")).thenReturn("true");
        when(realm.getAttribute("httpProxyHost")).thenReturn("web.proxy.svc.cluster.local");
        when(realm.getAttribute("httpProxyPort")).thenReturn(null);

        // When
        HttpClient client = HttpClientFactory.getHttpClient(realm);

        // Then
        assertNotNull(client);
        assertTrue(client.proxy().isEmpty());
    }
}
