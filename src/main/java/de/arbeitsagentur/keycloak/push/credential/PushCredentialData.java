package de.arbeitsagentur.keycloak.push.credential;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import org.keycloak.utils.StringUtil;

public class PushCredentialData {

    private final String publicKeyJwk;
    private final long createdAt;
    private final String deviceType;
    private final String pushProviderId;
    private final String pushProviderType;
    private final String credentialId;
    private final String deviceId;

    @JsonCreator
    public PushCredentialData(
            @JsonProperty("publicKeyJwk") String publicKeyJwk,
            @JsonProperty("createdAt") long createdAt,
            @JsonProperty("deviceType") String deviceType,
            @JsonProperty("pushProviderId") String pushProviderId,
            @JsonProperty("pushProviderType") String pushProviderType,
            @JsonProperty("credentialId") String credentialId,
            @JsonProperty("deviceId") String deviceId) {
        this.publicKeyJwk = publicKeyJwk;
        this.createdAt = createdAt;
        this.deviceType = deviceType;
        this.pushProviderId = pushProviderId;
        this.pushProviderType =
                StringUtil.isBlank(pushProviderType) ? PushMfaConstants.DEFAULT_PUSH_PROVIDER_TYPE : pushProviderType;
        this.credentialId = credentialId;
        this.deviceId = deviceId;
    }

    public String getPublicKeyJwk() {
        return publicKeyJwk;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public String getDeviceType() {
        return deviceType;
    }

    public String getPushProviderId() {
        return pushProviderId;
    }

    public String getPushProviderType() {
        return pushProviderType;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public String getDeviceId() {
        return deviceId;
    }
}
