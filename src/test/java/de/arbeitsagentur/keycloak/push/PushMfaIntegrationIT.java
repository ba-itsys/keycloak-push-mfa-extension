package de.arbeitsagentur.keycloak.push;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Testcontainers
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class PushMfaIntegrationIT {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path EXTENSION_JAR = locateProviderJar();
    private static final Path REALM_FILE = Paths.get("config", "push-mfa-realm.json").toAbsolutePath();

    private static final String DEVICE_CLIENT_ID = "push-device-client";
    private static final String DEVICE_CLIENT_SECRET = "device-client-secret";

    @Container
    private static final GenericContainer<?> KEYCLOAK = new GenericContainer<>("quay.io/keycloak/keycloak:26.4.2")
        .withExposedPorts(8080)
        .withCopyFileToContainer(MountableFile.forHostPath(EXTENSION_JAR), "/opt/keycloak/providers/keycloak-push-mfa.jar")
        .withCopyFileToContainer(MountableFile.forHostPath(REALM_FILE), "/opt/keycloak/data/import/push-mfa-realm.json")
        .withEnv("KEYCLOAK_ADMIN", "admin")
        .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
        .withEnv("KC_FEATURES", "dpop")
        .withEnv("JAVA_OPTS_APPEND", "-Dpush.mfa.test-mode=true")
        .withEnv("PUSH_MFA_TEST_MODE", "true")
        .withCommand("start-dev --hostname=localhost --hostname-strict=false --http-enabled=true --import-realm --features=dpop")
        .waitingFor(Wait.forHttp("/realms/master").forStatusCode(200))
        .withStartupTimeout(Duration.ofMinutes(3));

    private URI baseUri;

    @BeforeAll
    void setup() {
        baseUri = URI.create(String.format("http://%s:%d/", KEYCLOAK.getHost(), KEYCLOAK.getMappedPort(8080)));
    }

    @Test
    void deviceEnrollsAndApprovesLogin() throws Exception {
        try {
            DeviceState deviceState = DeviceState.create();
            DeviceClient deviceClient = new DeviceClient(baseUri, deviceState);

            BrowserSession enrollmentSession = new BrowserSession(baseUri);
            HtmlPage loginPage = enrollmentSession.startAuthorization("test-app");
            HtmlPage enrollmentPage = enrollmentSession.submitLogin(loginPage, "test", "test");
            String enrollmentToken = enrollmentSession.extractEnrollmentToken(enrollmentPage);
            deviceClient.completeEnrollment(enrollmentToken);
            enrollmentSession.submitEnrollmentCheck(enrollmentPage);

            BrowserSession pushSession = new BrowserSession(baseUri);
            HtmlPage pushLogin = pushSession.startAuthorization("test-app");
            HtmlPage waitingPage = pushSession.submitLogin(pushLogin, "test", "test");
            BrowserSession.DeviceChallenge confirm = pushSession.extractDeviceChallenge(waitingPage);
            deviceClient.respondToChallenge(confirm.confirmToken(), confirm.challengeId());
            pushSession.completePushChallenge(confirm.formAction());
        } catch (Exception ex) {
            System.err.println("Keycloak container logs:\n" + KEYCLOAK.getLogs());
            throw ex;
        }
    }

    private static Path locateProviderJar() {
        Path targetDir = Paths.get("target");
        if (!Files.isDirectory(targetDir)) {
            throw new IllegalStateException("target directory not found. Run mvn package before integration tests.");
        }
        try (var files = Files.list(targetDir)) {
            return files
                .filter(path -> path.getFileName().toString().startsWith("keycloak-push-mfa") && path.getFileName().toString().endsWith(".jar"))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Provider JAR not found. Run mvn package before integration tests."));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to inspect target directory", ex);
        }
    }

    private static final class DeviceState {
        final RSAKey key;
        final String deviceId = "device-" + UUID.randomUUID();
        final String pseudonymousId = "device-alias-" + UUID.randomUUID();
        final String firebaseId = "mock-firebase";
        final String deviceLabel = "Integration Test Device";
        String userId;

        private DeviceState(RSAKey key) {
            this.key = key;
        }

        static DeviceState create() throws Exception {
            RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyID("device-key-" + UUID.randomUUID())
                .algorithm(JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE)
                .generate();
            return new DeviceState(rsaKey);
        }
    }

    private static final class DeviceClient {
        private final URI realmBase;
        private final URI tokenEndpoint;
        private final DeviceState state;
        private final HttpClient http = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .build();
        private String accessToken;

        DeviceClient(URI baseUri, DeviceState state) {
            this.realmBase = baseUri.resolve("/realms/push-mfa/");
            this.tokenEndpoint = realmBase.resolve("protocol/openid-connect/token");
            this.state = state;
        }

        void completeEnrollment(String enrollmentToken) throws Exception {
            SignedJWT enrollment = SignedJWT.parse(enrollmentToken);
            JWTClaimsSet claims = enrollment.getJWTClaimsSet();
            state.userId = claims.getSubject();
            JWTClaimsSet deviceClaims = new JWTClaimsSet.Builder()
                .claim("enrollmentId", claims.getStringClaim("enrollmentId"))
                .claim("nonce", claims.getStringClaim("nonce"))
                .claim("sub", state.userId)
                .claim("deviceType", "ios")
                .claim("firebaseId", state.firebaseId)
                .claim("pseudonymousUserId", state.pseudonymousId)
                .claim("deviceId", state.deviceId)
                .claim("deviceLabel", state.deviceLabel)
                .expirationTime(java.util.Date.from(Instant.now().plusSeconds(300)))
                .claim("cnf", Map.of("jwk", state.key.toPublicJWK().toJSONObject()))
                .build();
            SignedJWT deviceToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).keyID(state.key.getKeyID()).build(),
                deviceClaims);
            deviceToken.sign(new RSASSASigner(state.key));

            HttpRequest request = HttpRequest.newBuilder(realmBase.resolve("push-mfa/enroll/complete"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(MAPPER.createObjectNode().put("token", deviceToken.serialize()).toString()))
                .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode(), () -> "Enrollment failed: " + response.body());
        }

        void respondToChallenge(String confirmToken, String challengeId) throws Exception {
            ensureAccessToken();
            SignedJWT confirm = SignedJWT.parse(confirmToken);
            String cid = Objects.requireNonNullElse(confirm.getJWTClaimsSet().getStringClaim("cid"), challengeId);
            JWTClaimsSet loginClaims = new JWTClaimsSet.Builder()
                .claim("cid", cid)
                .claim("sub", state.userId)
                .claim("deviceId", state.deviceId)
                .claim("action", "approve")
                .expirationTime(java.util.Date.from(Instant.now().plusSeconds(120)))
                .build();
            SignedJWT loginToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).keyID(state.key.getKeyID()).build(),
                loginClaims);
            loginToken.sign(new RSASSASigner(state.key));

            URI respondUri = realmBase.resolve("push-mfa/login/challenges/" + cid + "/respond");
            HttpRequest request = HttpRequest.newBuilder(respondUri)
                .header("Authorization", "DPoP " + accessToken)
                .header("DPoP", createDpopProof("POST", respondUri))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(MAPPER.createObjectNode().put("token", loginToken.serialize()).toString()))
                .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode(), () -> "Respond failed: " + response.body());
            assertEquals("approved", MAPPER.readTree(response.body()).path("status").asText());
        }

        private void ensureAccessToken() throws Exception {
            if (accessToken != null) {
                return;
            }
            HttpRequest request = HttpRequest.newBuilder(tokenEndpoint)
                .header("DPoP", createDpopProof("POST", tokenEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials&client_id="
                    + urlEncode(DEVICE_CLIENT_ID) + "&client_secret=" + urlEncode(DEVICE_CLIENT_SECRET)))
                .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode(), () -> "Token request failed: " + response.body());
            JsonNode json = MAPPER.readTree(response.body());
            accessToken = json.path("access_token").asText();
            if (accessToken != null && !accessToken.isBlank()) {
                var jwt = SignedJWT.parse(accessToken);
                System.err.println("Access token claims: " + jwt.getJWTClaimsSet().toJSONObject());
            }
            assertNotNull(accessToken);
        }

        private String createDpopProof(String method, URI uri) throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", method)
                .claim("htu", uri.toString())
                .claim("sub", state.userId)
                .claim("deviceId", state.deviceId)
                .claim("iat", Instant.now().getEpochSecond())
                .claim("jti", UUID.randomUUID().toString())
                .build();
            SignedJWT proof = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(new JOSEObjectType("dpop+jwt"))
                    .jwk(state.key.toPublicJWK())
                    .keyID(state.key.getKeyID())
                    .build(),
                claims);
            proof.sign(new RSASSASigner(state.key));
            return proof.serialize();
        }

        private String urlEncode(String value) {
            return URLEncoder.encode(value, StandardCharsets.UTF_8);
        }
    }

    private record HtmlPage(URI uri, Document document) {
    }

    private static final class BrowserSession {
        private final URI realmBase;
        private final HttpClient http;
        private final CookieManager cookieManager;
        private final String redirectUri = "http://localhost:8080/test-app/callback";
        private final String realmHost;
        private final int realmPort;

        BrowserSession(URI baseUri) {
            this.realmBase = baseUri.resolve("/realms/push-mfa/");
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

        HtmlPage startAuthorization(String clientId) throws Exception {
            String state = UUID.randomUUID().toString();
            String nonce = UUID.randomUUID().toString();
            String query = String.format(
                "client_id=%s&redirect_uri=%s&response_type=code&scope=openid&state=%s&nonce=%s",
                urlEncode(clientId),
                urlEncode(redirectUri),
                urlEncode(state),
                urlEncode(nonce));
            URI authUri = realmBase.resolve("protocol/openid-connect/auth?" + query);
            return fetch(authUri, "GET", null).requirePage();
        }

        HtmlPage submitLogin(HtmlPage loginPage, String username, String password) throws Exception {
            Element form = loginPage.document().selectFirst("form#kc-form-login");
            if (form == null) {
                throw new IllegalStateException("Login form not found");
            }
            Map<String, String> params = collectFormInputs(form);
            params.put("username", username);
            params.put("password", password);
            URI action = resolve(loginPage.uri(), form.attr("action"));
            return fetch(action, "POST", params).requirePage();
        }

        String extractEnrollmentToken(HtmlPage page) {
            Element token = page.document().getElementById("kc-push-token");
            if (token == null) {
                throw new IllegalStateException("Enrollment token block not found");
            }
            return token.text().trim();
        }

        void submitEnrollmentCheck(HtmlPage page) throws Exception {
            Element form = page.document().getElementById("kc-push-register-form");
            if (form == null) {
                throw new IllegalStateException("Enrollment form not found");
            }
            URI action = resolve(page.uri(), form.attr("action"));
            FetchResponse response = fetch(action, "POST", Map.of("check", "true"));
            assertEquals(302, response.status(), "Enrollment completion should redirect");
        }

        DeviceChallenge extractDeviceChallenge(HtmlPage page) {
            Element token = page.document().getElementById("kc-push-confirm-token");
            if (token == null) {
                throw new IllegalStateException("Confirm token block not found");
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

        void completePushChallenge(URI formAction) throws Exception {
            FetchResponse response = fetch(formAction, "POST", Map.of());
            assertEquals(302, response.status(), "Push completion should redirect");
        }

        private FetchResponse fetch(URI uri, String method, Map<String, String> params) throws Exception {
            URI current = uri;
            String currentMethod = method;
            String body = encodeForm(params);
            for (int i = 0; i < 10; i++) {
                HttpRequest.Builder builder = HttpRequest.newBuilder(current)
                    .header("Accept", "text/html,application/xhtml+xml");
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
                throw new IllegalStateException("Unexpected response " + status + " for " + current + ": " + response.body());
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
                if (builder.length() > 0) {
                    builder.append("; ");
                }
                builder.append(cookie.getName()).append('=').append(cookie.getValue());
            }
            return builder.toString();
        }

        private record DeviceChallenge(String confirmToken, String challengeId, URI formAction) {
        }

        private record FetchResponse(int status, URI uri, Document document, String redirectLocation) {
            HtmlPage requirePage() {
                if (document == null) {
                    throw new IllegalStateException("Expected HTML page from " + uri + " but received redirect to " + redirectLocation);
                }
                return new HtmlPage(uri, document);
            }
        }
    }

}
