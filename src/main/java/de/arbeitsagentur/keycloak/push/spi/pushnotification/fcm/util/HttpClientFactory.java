package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util;

import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.utils.StringUtil;

public class HttpClientFactory {

    private static final Logger LOG = Logger.getLogger(HttpClientFactory.class);

    private static final int CONNECTION_TIMEOUT_SECONDS = 10;

    private static HttpClient singletonInstance;

    private HttpClientFactory() {
        // Prevent instantiation
    }

    public static HttpClient getHttpClient(String url) {
        // Check NO_PROXY environment variable first to allow opt-out of proxying
        if (isHostInNoProxyList(url)) {
            LOG.debugf("URL %s is in NO_PROXY list, returning HttpClient without proxy", url);
            // singletonInstance without proxy?
            if (singletonInstance != null && !singletonInstance.proxy().isPresent()) {
                return singletonInstance;
            } else {
                LOG.debug("Existing HttpClient uses proxy, creating new instance without proxy for this request");
                return HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(CONNECTION_TIMEOUT_SECONDS))
                        .build();
            }
        }
        
        if (singletonInstance == null) {
            String proxy = null;
            List<String> proxyEnvVars = List.of("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY");
            for (String envVar : proxyEnvVars) {
                if (StringUtil.isNotBlank(ConfigUtil.getEnvString(envVar))) {
                    proxy = ConfigUtil.getEnvString(envVar);
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

    private static boolean isHostInNoProxyList(String url) {
        if (StringUtil.isBlank(url)) {
            return false;
        }
        String noProxyEnv = ConfigUtil.getEnvString("NO_PROXY");
        if (StringUtil.isNotBlank(noProxyEnv)) {
            List<String> noProxyHosts = List.of(noProxyEnv.split(","));
            try {                
                    URI uri = new URI(url);
                    String host = uri.getHost();
                    return noProxyHosts.contains(host);
                } catch (URISyntaxException e) {
                    LOG.warnf("Invalid URL syntax: %s", url);
                }
        }
        return false;
    }
}
