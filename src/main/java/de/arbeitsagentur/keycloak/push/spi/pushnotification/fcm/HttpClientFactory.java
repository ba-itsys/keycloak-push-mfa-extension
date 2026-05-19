package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm;

import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;
import org.keycloak.utils.StringUtil;

public class HttpClientFactory {

    private static final Logger LOG = Logger.getLogger(HttpClientFactory.class);

    private static final int CONNECTION_TIMEOUT_SECONDS = 10;

    private static HttpClient singletonInstance;

    private HttpClientFactory() {
        // Prevent instantiation
    }

    public static HttpClient getHttpClient(RealmModel realmModel) {
        if (singletonInstance == null) {
            String proxy = null;
            List<String> proxyEnvVars = List.of("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY");
            for (String envVar : proxyEnvVars) {
                if (StringUtil.isNotBlank(System.getenv(envVar))) {
                    proxy = System.getenv(envVar);
                    break;
                }
            }
            
            if (StringUtil.isNotBlank(proxy)) {
                try {
                    URI proxyUri = new URI(proxy);
                    InetSocketAddress proxyAddress = new InetSocketAddress(proxyUri.getHost(), proxyUri.getPort());
                    singletonInstance = HttpClient.newBuilder()
                            .connectTimeout(Duration.ofSeconds(CONNECTION_TIMEOUT_SECONDS))
                            .proxy(ProxySelector.of(proxyAddress))
                            .build();
                } catch (IllegalArgumentException | SecurityException | URISyntaxException e) {
                    LOG.warn("Error at creating proxy, proxying will be disabled: " + e.getMessage());
                    singletonInstance = HttpClient.newBuilder()
                            .connectTimeout(Duration.ofSeconds(CONNECTION_TIMEOUT_SECONDS))
                            .build();
                }
            } else {
                singletonInstance = HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(CONNECTION_TIMEOUT_SECONDS))
                        .build();
            }
        }
        return singletonInstance;
    }
}
