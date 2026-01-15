/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.arbeitsagentur.keycloak.push.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

public final class BrowserSession {

    private final URI realmBase;
    private final HttpClient http;
    private final CookieManager cookieManager;
    private final String redirectUri = "http://localhost:8080/test-app/callback";
    private final String realmHost;
    private final int realmPort;

    public BrowserSession(URI baseUri) {
        this.realmBase = baseUri.resolve("/realms/demo/");
        this.cookieManager = new CookieManager();
        this.cookieManager.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
        this.http = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .cookieHandler(this.cookieManager)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        this.realmHost = baseUri.getHost();
        this.realmPort = normalizePort(baseUri);
    }

    public String extractUserVerification(HtmlPage page) {
        if (page == null || page.document() == null) {
            return null;
        }
        Element verification = page.document().getElementById("kc-push-user-verification");
        if (verification == null) {
            return null;
        }
        String text = verification.text();
        return text == null ? null : text.trim();
    }

    public HtmlPage startAuthorization(String clientId) throws Exception {
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        String query = String.format(
                "client_id=%s&redirect_uri=%s&response_type=code&scope=openid&state=%s&nonce=%s",
                urlEncode(clientId), urlEncode(redirectUri), urlEncode(state), urlEncode(nonce));
        URI authUri = realmBase.resolve("protocol/openid-connect/auth?" + query);
        return fetch(authUri, "GET", null).requirePage();
    }

    public HtmlPage submitLogin(HtmlPage loginPage, String username, String password) throws Exception {
        PageOrRedirect result = submitLoginResult(loginPage, username, password, null);
        if (result.page() == null) {
            throw new IllegalStateException("Expected HTML page from " + result.uri() + " but received redirect to "
                    + result.redirectLocation());
        }
        return result.page();
    }

    public PageOrRedirect submitLoginResult(
            HtmlPage loginPage, String username, String password, Map<String, String> extraParams) throws Exception {
        Element form = loginPage.document().selectFirst("form#kc-form-login");
        if (form == null) {
            throw new IllegalStateException("Login form not found");
        }
        Map<String, String> params = collectFormInputs(form);
        params.put("username", username);
        params.put("password", password);
        if (extraParams != null && !extraParams.isEmpty()) {
            params.putAll(extraParams);
        }
        URI action = resolve(loginPage.uri(), form.attr("action"));
        FetchResponse response = fetch(action, "POST", params);
        if (response.document() == null) {
            return new PageOrRedirect(response.status(), response.uri(), null, response.redirectLocation());
        }
        return new PageOrRedirect(
                response.status(), response.uri(), new HtmlPage(response.uri(), response.document()), null);
    }

    public String extractEnrollmentToken(HtmlPage page) {
        Element token = page.document().getElementById("kc-push-token");
        if (token == null) {
            throw new IllegalStateException("Enrollment token block not found");
        }
        return token.text().trim();
    }

    public void submitEnrollmentCheck(HtmlPage page) throws Exception {
        Element form = page.document().getElementById("kc-push-register-form");
        if (form == null) {
            throw new IllegalStateException("Enrollment form not found");
        }
        URI action = resolve(page.uri(), form.attr("action"));
        FetchResponse response = fetch(action, "POST", Map.of("check", "true"));
        assertEquals(302, response.status(), "Enrollment completion should redirect");
        assertAccountConsoleAccessible();
    }

    public HtmlPage refreshEnrollmentChallenge(HtmlPage page) throws Exception {
        Element form = page.document().getElementById("kc-push-register-form");
        if (form == null) {
            throw new IllegalStateException("Enrollment form not found");
        }
        URI action = resolve(page.uri(), form.attr("action"));
        return fetch(action, "POST", Map.of("refresh", "true")).requirePage();
    }

    public URI extractEnrollmentEventsUri(HtmlPage page) {
        Element root = page.document().getElementById("kc-push-register-root");
        if (root == null) {
            throw new IllegalStateException("Enrollment root element missing");
        }
        String eventsUrl = root.attr("data-push-events-url");
        if (eventsUrl == null || eventsUrl.isBlank()) {
            throw new IllegalStateException("Enrollment events URL missing");
        }
        URI candidate = URI.create(eventsUrl);
        if (candidate.isAbsolute()) {
            return candidate;
        }
        return page.uri().resolve(candidate);
    }

    public String extractEnrollmentChallengeId(HtmlPage page) {
        URI uri = extractEnrollmentEventsUri(page);
        String[] segments = uri.getPath().split("/");
        for (int i = 0; i < segments.length; i++) {
            if ("challenges".equals(segments[i]) && i + 1 < segments.length) {
                return segments[i + 1];
            }
        }
        throw new IllegalStateException("Unable to extract challenge id from " + uri);
    }

    public DeviceChallenge extractDeviceChallenge(HtmlPage page) {
        Element token = page.document().getElementById("kc-push-confirm-token");
        if (token == null) {
            String body = page.document().text();
            if (body != null && body.length() > 240) {
                body = body.substring(0, 240) + "...";
            }
            throw new IllegalStateException("Confirm token block not found on page: " + body);
        }
        Element challengeInput = page.document().selectFirst("form#kc-push-form input[name=challengeId]");
        if (challengeInput == null) {
            throw new IllegalStateException("Challenge input missing");
        }
        Element form = page.document().selectFirst("form#kc-push-form");
        if (form == null) {
            throw new IllegalStateException("Push continuation form missing");
        }
        URI action = resolve(page.uri(), form.attr("action"));
        return new DeviceChallenge(token.text().trim(), challengeInput.attr("value"), action);
    }

    public String extractSameDeviceToken(HtmlPage page) {
        Element button = page.document().getElementById("kc-push-open-app");
        if (button == null) {
            throw new IllegalStateException("Same-device link button not found");
        }
        String url = button.attr("data-push-same-device-url");
        if (url == null || url.isBlank()) {
            throw new IllegalStateException("Same-device link URL missing");
        }
        URI link = URI.create(url);
        String query = link.getQuery();
        if (query == null || query.isBlank()) {
            throw new IllegalStateException("Same-device link missing token param");
        }
        for (String pair : query.split("&")) {
            String[] parts = pair.split("=", 2);
            if (parts.length == 2 && "token".equals(parts[0])) {
                return URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
            }
        }
        throw new IllegalStateException("Same-device link missing token param");
    }

    public void completePushChallenge(URI formAction) throws Exception {
        FetchResponse response = fetch(formAction, "POST", Map.of());
        if (response.status() == 302) {
            assertAccountConsoleAccessible();
            return;
        }
        assertEquals(200, response.status(), "Push completion should return success");
        assertAccountConsoleAccessible(response.requirePage());
    }

    public HtmlPage submitPushChallengeForPage(URI formAction) throws Exception {
        return fetch(formAction, "POST", Map.of()).requirePage();
    }

    public HtmlPage refreshPushChallenge(HtmlPage page) throws Exception {
        Element form = page.document().selectFirst("form#kc-push-form");
        if (form == null) {
            throw new IllegalStateException("Push continuation form missing");
        }
        Map<String, String> params = collectFormInputs(form);
        params.put("refresh", "true");
        URI action = resolve(page.uri(), form.attr("action"));
        return fetch(action, "POST", params).requirePage();
    }

    public HtmlPage retryPushChallenge(HtmlPage page) throws Exception {
        Element form = page.document().selectFirst("form");
        if (form == null) {
            throw new IllegalStateException("Push retry form missing");
        }
        URI action = resolve(page.uri(), form.attr("action"));
        return fetch(action, "POST", Map.of("retry", "true")).requirePage();
    }

    public HtmlPage reload(HtmlPage page) throws Exception {
        return fetch(page.uri(), "GET", null).requirePage();
    }

    private void assertAccountConsoleAccessible() throws Exception {
        URI accountUri = realmBase.resolve("account/");
        FetchResponse console = fetch(accountUri, "GET", null);
        assertEquals(200, console.status(), "Account console should load");
        assertAccountConsoleAccessible(console.requirePage());
    }

    private void assertAccountConsoleAccessible(HtmlPage page) {
        assertNotNull(page.document(), "Account console response missing HTML");
        Element appRoot = page.document().getElementById("app");
        assertNotNull(appRoot, "Account console root element not found");
    }

    private FetchResponse fetch(URI uri, String method, Map<String, String> params) throws Exception {
        URI current = uri;
        String currentMethod = method;
        String body = encodeForm(params);
        for (int i = 0; i < 10; i++) {
            HttpRequest.Builder builder =
                    HttpRequest.newBuilder(current).header("Accept", "text/html,application/xhtml+xml");
            if ("POST".equalsIgnoreCase(currentMethod)) {
                builder.header("Content-Type", "application/x-www-form-urlencoded");
                builder.POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
            } else {
                builder.GET();
            }
            String cookies = cookieHeader();
            if (!cookies.isBlank()) {
                builder.header("Cookie", cookies);
            }
            HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            normalizeCookieDomains();
            int status = response.statusCode();
            if (status >= 200 && status < 300) {
                return new FetchResponse(status, response.uri(), Jsoup.parse(response.body()), null);
            }
            if (isRedirect(status)) {
                String location = response.headers().firstValue("Location").orElseThrow();
                URI next = resolve(current, location);
                if (!isRealmHost(next)) {
                    return new FetchResponse(status, next, null, location);
                }
                current = next;
                currentMethod = "GET";
                body = null;
                continue;
            }
            throw new IllegalStateException(
                    "Unexpected response " + status + " for " + current + ": " + response.body());
        }
        throw new IllegalStateException("Too many redirects for " + uri);
    }

    private Map<String, String> collectFormInputs(Element form) {
        Map<String, String> params = new LinkedHashMap<>();
        for (Element input : form.select("input")) {
            String name = input.attr("name");
            if (name == null || name.isBlank()) {
                continue;
            }
            params.put(name, input.attr("value"));
        }
        return params;
    }

    private URI resolve(URI base, String action) {
        if (action == null || action.isBlank()) {
            return base;
        }
        return base.resolve(action);
    }

    private boolean isRealmHost(URI candidate) {
        if (candidate == null || candidate.getHost() == null) {
            return false;
        }
        int candidatePort = normalizePort(candidate);
        return candidate.getHost().equalsIgnoreCase(realmHost) && candidatePort == realmPort;
    }

    private int normalizePort(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private String encodeForm(Map<String, String> params) {
        if (params == null || params.isEmpty()) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!first) {
                builder.append('&');
            }
            builder.append(urlEncode(entry.getKey())).append('=').append(urlEncode(entry.getValue()));
            first = false;
        }
        return builder.toString();
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private boolean isRedirect(int status) {
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    private void normalizeCookieDomains() {
        cookieManager.getCookieStore().getCookies().stream()
                .filter(cookie -> "localhost.local".equalsIgnoreCase(cookie.getDomain()))
                .forEach(cookie -> cookie.setDomain("localhost"));
    }

    private String cookieHeader() {
        StringBuilder builder = new StringBuilder();
        for (HttpCookie cookie : cookieManager.getCookieStore().getCookies()) {
            if (!builder.isEmpty()) {
                builder.append("; ");
            }
            builder.append(cookie.getName()).append('=').append(cookie.getValue());
        }
        return builder.toString();
    }

    public HtmlPage triggerCredentialSetup(String requiredActionId) throws Exception {
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        String query = String.format(
                "client_id=test-app&redirect_uri=%s&response_type=code&scope=openid&state=%s&nonce=%s&kc_action=%s",
                urlEncode(redirectUri), urlEncode(state), urlEncode(nonce), urlEncode(requiredActionId));
        URI authUri = realmBase.resolve("protocol/openid-connect/auth?" + query);
        return fetch(authUri, "GET", null).requirePage();
    }

    public record DeviceChallenge(String confirmToken, String challengeId, URI formAction) {}

    public record PageOrRedirect(int status, URI uri, HtmlPage page, String redirectLocation) {}

    private record FetchResponse(int status, URI uri, Document document, String redirectLocation) {
        HtmlPage requirePage() {
            if (document == null) {
                throw new IllegalStateException(
                        "Expected HTML page from " + uri + " but received redirect to " + redirectLocation);
            }
            return new HtmlPage(uri, document);
        }
    }
}
