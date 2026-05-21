package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util.ConfigUtil;
import java.io.File;
import java.io.FileInputStream;
import org.jboss.logging.Logger;

@JsonIgnoreProperties(ignoreUnknown = true)
public class GoogleServiceAccountCred {

    private static final Logger LOG = Logger.getLogger(GoogleServiceAccountCred.class);

    @JsonProperty("type")
    private String type;

    @JsonProperty("project_id")
    private String projectId;

    @JsonProperty("private_key_id")
    private String privateKeyId;

    @JsonProperty("private_key")
    private String privateKey;

    @JsonProperty("client_email")
    private String clientEmail;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("token_uri")
    private String tokenUri;

    public GoogleServiceAccountCred() {}

    public GoogleServiceAccountCred(
            String type,
            String projectId,
            String privateKeyId,
            String privateKey,
            String clientEmail,
            String clientId,
            String tokenUri) {
        this.type = type;
        this.projectId = projectId;
        this.privateKeyId = privateKeyId;
        this.privateKey = privateKey;
        this.clientEmail = clientEmail;
        this.clientId = clientId;
        this.tokenUri = tokenUri;
    }

    public String getType() {
        return type;
    }

    public String getProjectId() {
        return projectId;
    }

    public String getPrivateKeyId() {
        return privateKeyId;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public String getClientEmail() {
        return clientEmail;
    }

    public String getClientId() {
        return clientId;
    }

    public String getTokenUri() {
        return tokenUri;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setProjectId(String projectId) {
        this.projectId = projectId;
    }

    public void setPrivateKeyId(String privateKeyId) {
        this.privateKeyId = privateKeyId;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public void setClientEmail(String clientEmail) {
        this.clientEmail = clientEmail;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setTokenUri(String tokenUri) {
        this.tokenUri = tokenUri;
    }

    public static GoogleServiceAccountCred loadFromFile() {
        String filePath = ConfigUtil.getEnvString("GOOGLE_APPLICATION_CREDENTIALS");
        if (filePath == null || filePath.isEmpty()) {
            LOG.warn("Environment variable GOOGLE_APPLICATION_CREDENTIALS is not set.");
            return null;
        }

        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            LOG.warnf("Google Service Account Credentials file not found: %s", filePath);
            return null;
        }

        GoogleServiceAccountCred credentials = null;
        try (FileInputStream fileInputStream = new FileInputStream(file)) {
            credentials = new ObjectMapper().readValue(fileInputStream, GoogleServiceAccountCred.class);
        } catch (Exception e) {
            LOG.warn("Error loading Google Service Account Credentials", e);
        }
        return credentials;
    }
}
