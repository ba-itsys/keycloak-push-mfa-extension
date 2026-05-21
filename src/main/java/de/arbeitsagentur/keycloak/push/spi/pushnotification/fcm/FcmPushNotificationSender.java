package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.push.spi.PushNotificationSender;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.FcmPushMessage;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.FcmPushRequestBody;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.GoogleServiceAccountCred;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.Notification;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.NotificationData;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util.HttpResult;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util.HttpTools;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.executors.ExecutorsProvider;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.theme.Theme;

public class FcmPushNotificationSender implements PushNotificationSender {
    private static final Logger LOG = Logger.getLogger(FcmPushNotificationSender.class);

    private static final String GOOGLE_FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
    private final String fcmUrl;

    public FcmPushNotificationSender(String fcmUrl) {
        this.fcmUrl = fcmUrl;
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
        Notification notification = getTranslatetedNotification(session, user);
        ExecutorsProvider provider = session.getProvider(ExecutorsProvider.class);

        // send notification without blocking
        CompletableFuture.runAsync(
                () -> {
                    NotificationSendResult result = null;
                    try {
                        result = sendNotification(confirmToken, pushProviderId, notification);
                    } catch (InterruptedException e) {
                        LOG.warn("Push notification interrupted", e);
                        Thread.currentThread().interrupt();
                    }
                    if (result != NotificationSendResult.SUCCESS) {
                        LOG.errorf(
                                "Failed to send push notification to user %s: %s",
                                user.getId(), Objects.requireNonNull(result).getMessage());
                    }
                },
                provider.getExecutor("firebase push provider"));
    }

    @Override
    public void close() {
        // close not needed
    }

    protected NotificationSendResult sendNotification(String confirmToken, String providerId, Notification notification)
            throws InterruptedException {
        // send confirmation push to firebase
        // 1. get google access token
        GoogleServiceAccountCred googleServiceAccountCred = GoogleServiceAccountCred.loadFromFile();
        if (googleServiceAccountCred == null) {
            return NotificationSendResult.NO_CREDENTIALS;
        }

        // get access token from googleServiceAccountCred.tokenUri
        String accessToken = getAccessToken(googleServiceAccountCred);
        if (accessToken == null) {
            return NotificationSendResult.TOKEN_REQUEST_FAILED;
        }

        // 2. send push notification to firebase with the provided token and payload
        NotificationData notificationData = new NotificationData(confirmToken);
        FcmPushMessage fcmPushMessage = new FcmPushMessage(providerId, notification, notificationData);
        FcmPushRequestBody requestBody = new FcmPushRequestBody(fcmPushMessage);

        if (!sendToFcm(this.fcmUrl, requestBody, accessToken)) {
            return NotificationSendResult.NOTIFICATION_SEND_FAILED;
        }
        return NotificationSendResult.SUCCESS;
    }

    protected Notification getTranslatetedNotification(KeycloakSession session, UserModel user) {
        final String TITLE_KEY = "push-mfa-notification-title";
        final String BODY_KEY = "push-mfa-notification-body";
        final String TITLE_DEFAULT = "Push MFA";
        final String BODY_DEFAULT = "Please confirm your login";

        Properties msg = new Properties();
        Locale locale = session.getContext().resolveLocale(user);
        try {
            Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
            Properties prop = theme.getMessages(locale);
            if (prop != null) {
                msg.putAll(prop);
            }
        } catch (IOException e) {
            LOG.warn("Error to load theme messages", e);
        }
        return new Notification(msg.getProperty(TITLE_KEY, TITLE_DEFAULT), msg.getProperty(BODY_KEY, BODY_DEFAULT));
    }

    private String getAccessToken(GoogleServiceAccountCred cred) throws InterruptedException {
        String jwt = createSignedJWT(cred);
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"));
        params.add(new BasicNameValuePair("assertion", jwt));

        HttpResult response;
        try {
            response = HttpTools.postTokenRequest(cred.getTokenUri(), params);
        } catch (IOException e) {
            LOG.warn("Exception at retrieving access token from FCM", e);
            return null;
        }
        if (response.statusCode() != 200) {
            LOG.warnf(
                    "Failed to retrieve access token from FCM: status: %d, body: %s",
                    response.statusCode(), response.body());
            return null;
        }

        Map<String, Object> responseJson;
        TypeReference<Map<String, Object>> typeRef = new TypeReference<>() {};
        try {
            responseJson = new ObjectMapper().readValue(response.body(), typeRef);
        } catch (JsonProcessingException e) {
            LOG.warn("Error parsing token response", e);
            return null;
        }
        return (String) responseJson.get("access_token");
    }

    private boolean sendToFcm(String url, FcmPushRequestBody requestBody, String accessToken)
            throws InterruptedException {
        if (url == null || url.isEmpty()) {
            LOG.warn("Missing FCM URL attribute");
            return false;
        }

        HttpResult response;
        try {
            response = HttpTools.postMessageRequest(url, requestBody, accessToken);
        } catch (IOException e) {
            LOG.warn("Exception at sending notification to FCM", e);
            return false;
        }

        if (response.statusCode() != 200) {
            LOG.warnf(
                    "Failed to send push notification to FCM: status: %d, body: %s",
                    response.statusCode(), response.body());
            return false;
        }
        LOG.debugf("Sent push notification to FCM: status: %d, body: %s", response.statusCode(), response.body());
        return true;
    }

    private String createSignedJWT(GoogleServiceAccountCred cred) {
        long exp = Time.currentTime() + 3600L;

        JsonWebToken jwt = new JsonWebToken();
        jwt.setSubject(cred.getClientEmail());
        jwt.issuer(cred.getClientEmail());
        jwt.addAudience(cred.getTokenUri());
        jwt.exp(exp);
        jwt.issuedNow();
        jwt.setOtherClaims("scope", GOOGLE_FCM_SCOPE);

        KeyWrapper key = new KeyWrapper();
        key.setAlgorithm("RS256");
        key.setPrivateKey(getPrivateKeyFromPem(cred.getPrivateKey()));
        SignatureSignerContext signerContext = new AsymmetricSignatureSignerContext(key);

        return new JWSBuilder().jsonContent(jwt).sign(signerContext);
    }

    private PrivateKey getPrivateKeyFromPem(String pem) {
        String privateKeyStr = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getMimeDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOG.warn(e);
        }
        return null;
    }
}
