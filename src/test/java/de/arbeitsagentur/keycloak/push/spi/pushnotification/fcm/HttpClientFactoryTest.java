package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util.ConfigUtil;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util.HttpClientFactory;
import java.lang.reflect.Field;
import java.net.URI;
import java.util.stream.Stream;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HttpContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.connections.httpclient.ProxyMappings;
import org.keycloak.connections.httpclient.ProxyMappingsAwareRoutePlanner;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class HttpClientFactoryTest {

    @Mock
    HttpClientBuilder builder;

    @Captor
    ArgumentCaptor<ProxyMappingsAwareRoutePlanner> proxyCaptor;

    @AfterEach
    public void reset() {
        try {
            Field clientField = HttpClientFactory.class.getDeclaredField("cachedProxyMappings");
            clientField.setAccessible(true);
            clientField.set(null, null);
        } catch (Exception e) {
            // Ignore exceptions during cleanup
        }
        Mockito.reset(builder);
        ProxyMappings.clearCache();
    }

    @Test
    public void shouldCreateHttpClientWithoutProxy() {
        // Given

        // When
        CloseableHttpClient client = HttpClientFactory.getHttpClient();

        // Then
        assertNotNull(client);
        assertTrue(client instanceof CloseableHttpClient);
    }

    @Test
    public void shouldCreateHttpClientWithProxy() throws Exception {
        // Given
        URI expectedProxyUri = new URI("https://web.proxy.svc.cluster.local:8081");

        // When
        try (MockedStatic<ConfigUtil> mockedConfigUtil = Mockito.mockStatic(ConfigUtil.class);
                MockedStatic<HttpClientBuilder> mockedHttpClientBuilder = Mockito.mockStatic(HttpClientBuilder.class)) {
            mockedConfigUtil.when(() -> ConfigUtil.getEnvString("HTTPS_PROXY")).thenReturn(expectedProxyUri.toString());

            when(builder.setConnectionTimeToLive(Mockito.anyLong(), Mockito.any()))
                    .thenReturn(builder);
            when(builder.setRoutePlanner(Mockito.any(ProxyMappingsAwareRoutePlanner.class)))
                    .thenReturn(builder);
            mockedHttpClientBuilder.when(HttpClientBuilder::create).thenReturn(builder);

            HttpClientFactory.getHttpClient();

            // Then
            verify(builder).setConnectionTimeToLive(10, java.util.concurrent.TimeUnit.SECONDS);
            verify(builder).setRoutePlanner(proxyCaptor.capture());

            ProxyMappingsAwareRoutePlanner routePlanner = proxyCaptor.getValue();
            assertNotNull(routePlanner);
            HttpRoute route = routePlanner.determineRoute(
                    new HttpHost("test.com"), mock(HttpRequest.class), mock(HttpContext.class));
            assertNotNull(route);

            HttpHost proxyHost = route.getProxyHost();
            assertNotNull(proxyHost);
            assertEquals(expectedProxyUri.getHost(), proxyHost.getHostName());
            assertEquals(expectedProxyUri.getPort(), proxyHost.getPort());
        }
    }

    @ParameterizedTest
    @MethodSource("provideProxyEnv")
    public void shouldCreateHttpClientWithProxyEnvPrecedence(String env1, String value1, String env2, String value2)
            throws Exception {
        // Given

        // When
        try (MockedStatic<ConfigUtil> mockedConfigUtil = Mockito.mockStatic(ConfigUtil.class);
                MockedStatic<HttpClientBuilder> mockedHttpClientBuilder = Mockito.mockStatic(HttpClientBuilder.class)) {
            mockedConfigUtil.when(() -> ConfigUtil.getEnvString(env1)).thenReturn(value1);
            mockedConfigUtil.when(() -> ConfigUtil.getEnvString(env2)).thenReturn(value2);

            when(builder.setConnectionTimeToLive(Mockito.anyLong(), Mockito.any()))
                    .thenReturn(builder);
            when(builder.setRoutePlanner(Mockito.any(ProxyMappingsAwareRoutePlanner.class)))
                    .thenReturn(builder);
            mockedHttpClientBuilder.when(HttpClientBuilder::create).thenReturn(builder);

            HttpClientFactory.getHttpClient();

            // Then
            verify(builder).setConnectionTimeToLive(10, java.util.concurrent.TimeUnit.SECONDS);
            verify(builder).setRoutePlanner(proxyCaptor.capture());

            ProxyMappingsAwareRoutePlanner routePlanner = proxyCaptor.getValue();
            assertNotNull(routePlanner);
            HttpRoute route = routePlanner.determineRoute(
                    new HttpHost("test.com"), mock(HttpRequest.class), mock(HttpContext.class));
            assertNotNull(route);

            URI expectedProxyUri = new URI(value2);
            HttpHost proxyHost = route.getProxyHost();
            assertNotNull(proxyHost);
            assertEquals(expectedProxyUri.getHost(), proxyHost.getHostName());
            assertEquals(expectedProxyUri.getPort(), proxyHost.getPort());
        }
    }

    @Test
    public void shouldCreateHttpClientWithProxyNoProxy() throws Exception {
        // Given
        URI expectedProxyUri = new URI("https://web.proxy.svc.cluster.local:8081");

        // When
        try (MockedStatic<ConfigUtil> mockedConfigUtil = Mockito.mockStatic(ConfigUtil.class);
                MockedStatic<HttpClientBuilder> mockedHttpClientBuilder = Mockito.mockStatic(HttpClientBuilder.class)) {
            mockedConfigUtil.when(() -> ConfigUtil.getEnvString("HTTPS_PROXY")).thenReturn(expectedProxyUri.toString());
            mockedConfigUtil.when(() -> ConfigUtil.getEnvString("NO_PROXY")).thenReturn("test.com");

            when(builder.setConnectionTimeToLive(Mockito.anyLong(), Mockito.any()))
                    .thenReturn(builder);
            when(builder.setRoutePlanner(Mockito.any(ProxyMappingsAwareRoutePlanner.class)))
                    .thenReturn(builder);
            mockedHttpClientBuilder.when(HttpClientBuilder::create).thenReturn(builder);

            HttpClientFactory.getHttpClient();

            // Then
            verify(builder).setConnectionTimeToLive(10, java.util.concurrent.TimeUnit.SECONDS);
            verify(builder).setRoutePlanner(proxyCaptor.capture());

            ProxyMappingsAwareRoutePlanner routePlanner = proxyCaptor.getValue();
            assertNotNull(routePlanner);
            HttpRoute route = routePlanner.determineRoute(
                    new HttpHost("test.com"), mock(HttpRequest.class), mock(HttpContext.class));
            assertNotNull(route);

            HttpHost proxyHost = route.getProxyHost();
            assertNull(proxyHost);
        }
    }

    @Test
    public void shouldCreateHttpClientNoProxyPrecedence() throws Exception {
        // Given
        URI expectedProxyUri = new URI("https://web.proxy.svc.cluster.local:8081");

        // When
        try (MockedStatic<ConfigUtil> mockedConfigUtil = Mockito.mockStatic(ConfigUtil.class);
                MockedStatic<HttpClientBuilder> mockedHttpClientBuilder = Mockito.mockStatic(HttpClientBuilder.class)) {
            mockedConfigUtil.when(() -> ConfigUtil.getEnvString("HTTPS_PROXY")).thenReturn(expectedProxyUri.toString());
            mockedConfigUtil.when(() -> ConfigUtil.getEnvString("NO_PROXY")).thenReturn("abc.net");
            mockedConfigUtil.when(() -> ConfigUtil.getEnvString("no_proxy")).thenReturn("test.com");

            when(builder.setConnectionTimeToLive(Mockito.anyLong(), Mockito.any()))
                    .thenReturn(builder);
            when(builder.setRoutePlanner(Mockito.any(ProxyMappingsAwareRoutePlanner.class)))
                    .thenReturn(builder);
            mockedHttpClientBuilder.when(HttpClientBuilder::create).thenReturn(builder);

            HttpClientFactory.getHttpClient();

            // Then
            verify(builder).setConnectionTimeToLive(10, java.util.concurrent.TimeUnit.SECONDS);
            verify(builder).setRoutePlanner(proxyCaptor.capture());

            ProxyMappingsAwareRoutePlanner routePlanner = proxyCaptor.getValue();
            assertNotNull(routePlanner);
            HttpRoute route = routePlanner.determineRoute(
                    new HttpHost("test.com"), mock(HttpRequest.class), mock(HttpContext.class));
            assertNotNull(route);

            HttpHost proxyHost = route.getProxyHost();
            assertNull(proxyHost);
        }
    }

    @Test
    public void shouldAlwaysCreateNewHttpClient() {
        // Given

        // When
        CloseableHttpClient client1 = HttpClientFactory.getHttpClient();
        CloseableHttpClient client2 = HttpClientFactory.getHttpClient();

        // Then
        assertNotNull(client1);
        assertNotNull(client2);
        assertTrue(client1 != client2);
    }

    private static Stream<Arguments> provideProxyEnv() {
        return Stream.of(
                Arguments.of("HTTPS_PROXY", "http://proxy1.com:3000", "https_proxy", "http://proxy2.com:5000"),
                Arguments.of("HTTP_PROXY", "http://proxy1.com:3000", "https_proxy", "http://proxy2.com:5000"),
                Arguments.of("HTTP_PROXY", "http://proxy1.com:3000", "HTTPS_PROXY", "http://proxy2.com:5000"),
                Arguments.of("HTTP_PROXY", "http://proxy1.com:3000", "http_proxy", "http://proxy2.com:5000"));
    }
}
