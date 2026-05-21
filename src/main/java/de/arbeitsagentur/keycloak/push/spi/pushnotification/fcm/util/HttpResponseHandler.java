package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util;

import java.io.IOException;
import org.apache.http.HttpResponse;
import org.apache.http.client.ResponseHandler;

public class HttpResponseHandler implements ResponseHandler<HttpResult> {
    @Override
    public HttpResult handleResponse(HttpResponse response) throws IOException {
        int status = response.getStatusLine().getStatusCode();
        String content = response.getEntity() != null
                ? new String(response.getEntity().getContent().readAllBytes())
                : "";
        return new HttpResult(status, content);
    }
}
