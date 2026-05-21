package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.FcmPushRequestBody;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.GoogleServiceAccountCred;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.Notification;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util.HttpResult;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util.HttpTools;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import org.jboss.logging.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.ThemeManager;
import org.keycloak.models.UserModel;
import org.keycloak.theme.Theme;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class FcmPushNotificationSenderTest {
    @Mock
    KeycloakSession session;

    @Mock
    RealmModel realm;

    @Mock
    UserModel user;

    @Mock
    ThemeManager manager;

    GoogleServiceAccountCred cred = new GoogleServiceAccountCred();
    NotificationSendResult result;
    Notification sentNotification;

    @BeforeEach
    public void setup() throws NoSuchAlgorithmException, IOException {
        cred.setType("service_account");
        cred.setProjectId("push-mfa-app");
        cred.setClientEmail("push-mfa@test.de");
        cred.setPrivateKeyId("key-id");
        cred.setPrivateKey(getPrivateKeyPem());
        cred.setTokenUri("https://oauth2.googleapis.com/token");

        when(session.getContext()).thenReturn(mock(KeycloakContext.class));
        when(manager.getTheme(Theme.Type.LOGIN)).thenReturn(mock(Theme.class));
        when(session.theme()).thenReturn(manager);

        sentNotification = null;
        result = null;
    }

    @Test
    public void testSendPushNotification() {
        String fcmUrl = "https://fcm.googleapis.com/fcm/send";
        FcmPushNotificationSender provider = new FcmPushNotificationSenderTestImpl(fcmUrl);

        try (MockedStatic<HttpTools> httpTools = mockStatic(HttpTools.class);
                MockedStatic<GoogleServiceAccountCred> googleCred = mockStatic(GoogleServiceAccountCred.class)) {

            googleCred.when(GoogleServiceAccountCred::loadFromFile).thenReturn(cred);

            String jwt = "dummy-jwt-token";
            HttpResult tokenResponse = new HttpResult(200, "{\"access_token\":\"" + jwt + "\"}");
            httpTools
                    .when(() -> HttpTools.postTokenRequest(Mockito.anyString(), Mockito.any()))
                    .thenReturn(tokenResponse);

            HttpResult messageResponse = new HttpResult(200, "OK");
            httpTools
                    .when(() -> HttpTools.postMessageRequest(Mockito.anyString(), Mockito.any(), Mockito.anyString()))
                    .thenReturn(messageResponse);

            provider.send(
                    session, realm, user, "confirmToken", "credentialId", "challengeId", "provider-id", "client-id");

            Notification expectedNotification = new Notification("Push MFA", "Please confirm your login");

            assertEquals(expectedNotification.getTitle(), sentNotification.getTitle());
            assertEquals(expectedNotification.getBody(), sentNotification.getBody());
            httpTools.verify(() -> HttpTools.postTokenRequest(Mockito.anyString(), Mockito.any()));
            httpTools.verify(
                    () -> HttpTools.postMessageRequest(eq(fcmUrl), Mockito.any(FcmPushRequestBody.class), eq(jwt)));
            assertEquals(NotificationSendResult.SUCCESS, result);
        }
    }

    @Test
    public void testSendPushNotificationFailedTokenRequest() {
        String fcmUrl = "https://fcm.googleapis.com/fcm/send";
        FcmPushNotificationSender provider = new FcmPushNotificationSenderTestImpl(fcmUrl);

        try (MockedStatic<HttpTools> httpTools = mockStatic(HttpTools.class);
                MockedStatic<GoogleServiceAccountCred> googleCred = mockStatic(GoogleServiceAccountCred.class)) {

            googleCred.when(GoogleServiceAccountCred::loadFromFile).thenReturn(cred);

            HttpResult tokenResponse = new HttpResult(500, "Internal Server Error");
            httpTools
                    .when(() -> HttpTools.postTokenRequest(Mockito.anyString(), Mockito.any()))
                    .thenReturn(tokenResponse);

            provider.send(
                    session, realm, user, "confirmToken", "credentialId", "challengeId", "provider-id", "client-id");

            httpTools.verify(() -> HttpTools.postTokenRequest(Mockito.anyString(), Mockito.any()));
            httpTools.verify(
                    () -> HttpTools.postMessageRequest(
                            Mockito.anyString(), Mockito.any(FcmPushRequestBody.class), Mockito.anyString()),
                    never());
            assertEquals(NotificationSendResult.TOKEN_REQUEST_FAILED, result);
        }
    }

    @Test
    public void testSendPushNotificationTokenRequestException() {
        String fcmUrl = "https://fcm.googleapis.com/fcm/send";
        FcmPushNotificationSender provider = new FcmPushNotificationSenderTestImpl(fcmUrl);

        try (MockedStatic<HttpTools> httpTools = mockStatic(HttpTools.class);
                MockedStatic<GoogleServiceAccountCred> googleCred = mockStatic(GoogleServiceAccountCred.class)) {

            googleCred.when(GoogleServiceAccountCred::loadFromFile).thenReturn(cred);

            httpTools
                    .when(() -> HttpTools.postTokenRequest(Mockito.anyString(), Mockito.any()))
                    .thenThrow(new IOException("Failed to complete request after 3 retries"));

            provider.send(
                    session, realm, user, "confirmToken", "credentialId", "challengeId", "provider-id", "client-id");

            httpTools.verify(() -> HttpTools.postTokenRequest(Mockito.anyString(), Mockito.any()));
            httpTools.verify(
                    () -> HttpTools.postMessageRequest(
                            Mockito.anyString(), Mockito.any(FcmPushRequestBody.class), Mockito.anyString()),
                    never());
            assertEquals(NotificationSendResult.TOKEN_REQUEST_FAILED, result);
        }
    }

    @Test
    public void testSendPushNotificationTokenRequestBodyParceException() {
        String fcmUrl = "https://fcm.googleapis.com/fcm/send";
        FcmPushNotificationSender provider = new FcmPushNotificationSenderTestImpl(fcmUrl);

        try (MockedStatic<HttpTools> httpTools = mockStatic(HttpTools.class);
                MockedStatic<GoogleServiceAccountCred> googleCred = mockStatic(GoogleServiceAccountCred.class)) {

            googleCred.when(GoogleServiceAccountCred::loadFromFile).thenReturn(cred);

            HttpResult tokenResponse = new HttpResult(200, "invalid-json");
            httpTools
                    .when(() -> HttpTools.postTokenRequest(Mockito.anyString(), Mockito.any()))
                    .thenReturn(tokenResponse);

            provider.send(
                    session, realm, user, "confirmToken", "credentialId", "challengeId", "provider-id", "client-id");

            httpTools.verify(() -> HttpTools.postTokenRequest(Mockito.anyString(), Mockito.any()));
            httpTools.verify(
                    () -> HttpTools.postMessageRequest(
                            Mockito.anyString(), Mockito.any(FcmPushRequestBody.class), Mockito.anyString()),
                    never());
            assertEquals(NotificationSendResult.TOKEN_REQUEST_FAILED, result);
        }
    }

    @Test
    public void testSendPushNotificationNoFcmUrl() {
        FcmPushNotificationSender provider = new FcmPushNotificationSenderTestImpl(null);

        try (MockedStatic<HttpTools> httpTools = mockStatic(HttpTools.class);
                MockedStatic<GoogleServiceAccountCred> googleCred = mockStatic(GoogleServiceAccountCred.class)) {

            googleCred.when(GoogleServiceAccountCred::loadFromFile).thenReturn(cred);

            String jwt = "dummy-jwt-token";
            HttpResult tokenResponse = new HttpResult(200, "{\"access_token\":\"" + jwt + "\"}");
            httpTools
                    .when(() -> HttpTools.postTokenRequest(Mockito.anyString(), Mockito.any()))
                    .thenReturn(tokenResponse);

            HttpResult messageResponse = new HttpResult(200, "OK");
            httpTools
                    .when(() -> HttpTools.postMessageRequest(
                            Mockito.anyString(), Mockito.any(FcmPushRequestBody.class), Mockito.anyString()))
                    .thenReturn(messageResponse);

            provider.send(
                    session, realm, user, "confirmToken", "credentialId", "challengeId", "provider-id", "client-id");

            httpTools.verify(() -> HttpTools.postTokenRequest(Mockito.anyString(), Mockito.any()));
            httpTools.verify(
                    () -> HttpTools.postMessageRequest(
                            Mockito.anyString(), Mockito.any(FcmPushRequestBody.class), Mockito.anyString()),
                    never());
            assertEquals(NotificationSendResult.NOTIFICATION_SEND_FAILED, result);
        }
    }

    @Test
    public void testSendPushNotificationSendFailed() {
        String fcmUrl = "https://fcm.googleapis.com/fcm/send";
        FcmPushNotificationSender provider = new FcmPushNotificationSenderTestImpl(fcmUrl);

        try (MockedStatic<HttpTools> httpTools = mockStatic(HttpTools.class);
                MockedStatic<GoogleServiceAccountCred> googleCred = mockStatic(GoogleServiceAccountCred.class)) {

            googleCred.when(GoogleServiceAccountCred::loadFromFile).thenReturn(cred);

            String jwt = "dummy-jwt-token";
            HttpResult tokenResponse = new HttpResult(200, "{\"access_token\":\"" + jwt + "\"}");
            httpTools
                    .when(() -> HttpTools.postTokenRequest(Mockito.anyString(), Mockito.any()))
                    .thenReturn(tokenResponse);

            HttpResult messageResponse = new HttpResult(500, "Internal Server Error");
            httpTools
                    .when(() -> HttpTools.postMessageRequest(Mockito.anyString(), Mockito.any(), Mockito.anyString()))
                    .thenReturn(messageResponse);

            provider.send(
                    session, realm, user, "confirmToken", "credentialId", "challengeId", "provider-id", "client-id");

            httpTools.verify(() -> HttpTools.postTokenRequest(Mockito.anyString(), Mockito.any()));
            httpTools.verify(
                    () -> HttpTools.postMessageRequest(eq(fcmUrl), Mockito.any(FcmPushRequestBody.class), eq(jwt)));
            assertEquals(NotificationSendResult.NOTIFICATION_SEND_FAILED, result);
        }
    }

    @Test
    public void testSendPushNotificationSendException() {
        String fcmUrl = "https://fcm.googleapis.com/fcm/send";
        FcmPushNotificationSender provider = new FcmPushNotificationSenderTestImpl(fcmUrl);

        try (MockedStatic<HttpTools> httpTools = mockStatic(HttpTools.class);
                MockedStatic<GoogleServiceAccountCred> googleCred = mockStatic(GoogleServiceAccountCred.class)) {

            googleCred.when(GoogleServiceAccountCred::loadFromFile).thenReturn(cred);

            String jwt = "dummy-jwt-token";
            HttpResult tokenResponse = new HttpResult(200, "{\"access_token\":\"" + jwt + "\"}");
            httpTools
                    .when(() -> HttpTools.postTokenRequest(Mockito.anyString(), Mockito.any()))
                    .thenReturn(tokenResponse);

            httpTools
                    .when(() -> HttpTools.postMessageRequest(Mockito.anyString(), Mockito.any(), Mockito.anyString()))
                    .thenThrow(new IOException("Failed to complete request after 3 retries"));

            provider.send(
                    session, realm, user, "confirmToken", "credentialId", "challengeId", "provider-id", "client-id");

            httpTools.verify(() -> HttpTools.postTokenRequest(Mockito.anyString(), Mockito.any()));
            httpTools.verify(
                    () -> HttpTools.postMessageRequest(eq(fcmUrl), Mockito.any(FcmPushRequestBody.class), eq(jwt)));
            assertEquals(NotificationSendResult.NOTIFICATION_SEND_FAILED, result);
        }
    }

    private String getPrivateKeyPem() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        if (!(privateKey instanceof RSAPrivateKey)) {
            throw new IllegalStateException("Generated key is not an RSA private key");
        }

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        byte[] keyBytes = keySpec.getEncoded();
        String base64Key = Base64.getEncoder().encodeToString(keyBytes);

        StringBuilder pemPrivateKey = new StringBuilder();
        pemPrivateKey.append("-----BEGIN PRIVATE KEY-----");
        pemPrivateKey.append(base64Key);
        pemPrivateKey.append("-----END PRIVATE KEY-----");
        return pemPrivateKey.toString();
    }

    class FcmPushNotificationSenderTestImpl extends FcmPushNotificationSender {
        private static final Logger LOG = Logger.getLogger(FcmPushNotificationSender.class);

        public FcmPushNotificationSenderTestImpl(String fcmUrl) {
            super(fcmUrl);
        }

        @Override
        public void send(
                KeycloakSession session,
                RealmModel realm,
                UserModel user,
                String confirmToken,
                String deviceCredentialId,
                String challengeId,
                String pushProviderId,
                String clientId) {

            sentNotification = super.getTranslatetedNotification(session, user);
            try {
                result = super.sendNotification(confirmToken, pushProviderId, sentNotification);
            } catch (InterruptedException e) {
                LOG.error("Interrupted exception occurred", e);
            }
        }
    }
}
