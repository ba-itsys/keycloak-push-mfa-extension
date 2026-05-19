package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.Proxy;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util.ConfigUtil;

@ExtendWith(MockitoExtension.class)
public class HttpClientFactoryTest {
    public static final String CHILD_PROCESS_TAG = "child_process";
    public static final String TAG = String.format("-Dgroups=%s", CHILD_PROCESS_TAG);
    private final String testClass = String.format("-Dtest=%s", getClass().getName());
    private final String[] arguments = {"mvn", "test", TAG, testClass};

    @AfterEach
    void cleanUp() {
        try {
            Field clientField = HttpClientFactory.class.getDeclaredField("singletonInstance");
            clientField.setAccessible(true);
            clientField.set(null, null);
        } catch (Exception e) {
            // Ignore exceptions during cleanup
        }
    }

    @Test
    void givenChildProcessTestRunner_whenRunTheTest_thenAllSucceed()
    throws IOException, InterruptedException {
        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.inheritIO();

        Map<String, String> environment = processBuilder.environment();
        environment.put("WITH_PROXY", "true");
        environment.put("HTTPS_PROXY", "web.proxy.svc.cluster.local:8081");
        Process process = processBuilder.command(arguments).start();

        int errorCode = process.waitFor();
        assertEquals(0, errorCode);
    }


    @Test
    public void shouldCreateHttpClientWithoutProxy() {
        // Given
        String url = "http://test.com/messages:send";

        // When
        HttpClient client = HttpClientFactory.getHttpClient(url);

        // Then
        assertNotNull(client);
        assertTrue(client.proxy().isEmpty());
    }

    @Test
    public void shouldCreateHttpClientWithProxy() throws Exception {
        // Given
        String url = "http://test.com/messages:send";

        // When
        try (MockedStatic<ConfigUtil> mockedConfigUtil = Mockito.mockStatic(ConfigUtil.class)) {
            mockedConfigUtil.when(() -> ConfigUtil.getEnvString("HTTPS_PROXY")).thenReturn("https://web.proxy.svc.cluster.local:8081");

            HttpClient client = HttpClientFactory.getHttpClient(url);

            // Then
            assertNotNull(client);
            assertTrue(client.proxy().isPresent());
            List<Proxy> proxies = client.proxy().get().select(new URI("http://test.com/messages:send"));
            assertTrue(proxies.getFirst().address().toString().contains("web.proxy.svc.cluster.local"));
            assertTrue(proxies.getFirst().address().toString().contains(":8081"));
        }
    }

    @Test
    public void shouldCreateHttpClientOnlyOnce() {
        // Given
        String url = "http://test.com/messages:send";

        // When
        HttpClient client1 = HttpClientFactory.getHttpClient(url);
        HttpClient client2 = HttpClientFactory.getHttpClient(url);

        // Then
        assertNotNull(client1);
        assertNotNull(client2);
        assertEquals(client1, client2);
    }
}
