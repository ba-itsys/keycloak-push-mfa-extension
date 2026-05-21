package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.ProxyMappings;
import org.keycloak.connections.httpclient.ProxyMappingsAwareRoutePlanner;
import org.keycloak.utils.StringUtil;

public class HttpClientFactory {
    private static final Logger LOG = Logger.getLogger(HttpClientFactory.class);

    private static final int CONNECTION_TIMEOUT_SECONDS = 10;
    private static ProxyMappings cachedProxyMappings;

    private HttpClientFactory() {
        // Prevent instantiation
    }

    public static CloseableHttpClient getHttpClient() {
        HttpClientBuilder builder =
                HttpClientBuilder.create().setConnectionTimeToLive(CONNECTION_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        ProxyMappings proxyMappings = getProxyMappings();
        if (proxyMappings != null && !proxyMappings.isEmpty()) {
            builder.setRoutePlanner(new ProxyMappingsAwareRoutePlanner(proxyMappings));
        }
        configureRetries(builder);
        return builder.build();
    }

    private static ProxyMappings getProxyMappings() {
        if (cachedProxyMappings != null) {
            return cachedProxyMappings;
        }
        String proxy = null;
        // check environment variables for proxy settings, with precedence: https_proxy > http_proxy
        List<String> proxyEnvVars = List.of("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY");
        for (String envVar : proxyEnvVars) {
            if (StringUtil.isNotBlank(ConfigUtil.getEnvString(envVar))) {
                proxy = ConfigUtil.getEnvString(envVar);
                break;
            }
        }
        String noProxy = ConfigUtil.getEnvString("no_proxy") != null
                ? ConfigUtil.getEnvString("no_proxy")
                : ConfigUtil.getEnvString("NO_PROXY");

        LOG.debugf("httpProxy: %s, noProxy: %s", proxy, noProxy);
        cachedProxyMappings = ProxyMappings.withFixedProxyMapping(proxy, noProxy);
        return cachedProxyMappings;
    }

    private static void configureRetries(HttpClientBuilder builder) {
        // Always enable request-sent retries for common requests (e.g., GET, POST)
        int maxRetries = 2;
        long initialBackoffMillis = 1000L;
        double backoffMultiplier = 2.0;
        double jitterFactor = 0.5;

        builder.setRetryHandler(new DefaultHttpRequestRetryHandler(maxRetries, true) {
            @Override
            public boolean retryRequest(
                    IOException exception, int executionCount, org.apache.http.protocol.HttpContext context) {
                boolean shouldRetry = super.retryRequest(exception, executionCount, context);
                if (shouldRetry) {
                    try {
                        long baseDelay = initialBackoffMillis * (long) Math.pow(backoffMultiplier, executionCount - 1);
                        double jitter = 1.0 - jitterFactor + (Math.random() * jitterFactor * 2.0);
                        long delay = (long) (baseDelay * jitter);

                        Thread.sleep(delay);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                return shouldRetry;
            }
        });
    }
}
