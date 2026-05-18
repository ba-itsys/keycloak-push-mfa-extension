package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm;

import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.time.Duration;
import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;

public class HttpClientFactory {

    private static final Logger LOG = Logger.getLogger(HttpClientFactory.class);

    private static final int CONNECTION_TIMEOUT_SECONDS = 10;

    private static HttpClient singletonInstance;

    private HttpClientFactory() {
        // Prevent instantiation
    }

    public static HttpClient getHttpClient(RealmModel realmModel) {
        if (singletonInstance == null) {
            String proxyEnabled = realmModel.getAttribute("httpProxyEnabled");
            if ("true".equalsIgnoreCase(proxyEnabled)) {
                try {
                    String proxyHost = realmModel.getAttribute("httpProxyHost");
                    int proxyPort = Integer.parseInt(realmModel.getAttribute("httpProxyPort"));
                    InetSocketAddress proxyAddress = new InetSocketAddress(proxyHost, proxyPort);
                    singletonInstance = HttpClient.newBuilder()
                            .connectTimeout(Duration.ofSeconds(CONNECTION_TIMEOUT_SECONDS))
                            .proxy(ProxySelector.of(proxyAddress))
                            .build();
                } catch (IllegalArgumentException | SecurityException e) {
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
