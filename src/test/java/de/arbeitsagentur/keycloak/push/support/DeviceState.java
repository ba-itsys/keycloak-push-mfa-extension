package de.arbeitsagentur.keycloak.push.support;

import java.util.UUID;

public final class DeviceState {

    private DeviceSigningKey key;
    private final String deviceId = "device-" + UUID.randomUUID();
    private final String credentialId = "credential-" + UUID.randomUUID();
    private String pushProviderId = "mock-push-provider";
    private String pushProviderType = "log";
    private final String deviceLabel = "Integration Test Device";
    private String userId;

    private DeviceState(DeviceSigningKey key) {
        this.key = key;
    }

    public static DeviceState create(DeviceKeyType keyType) throws Exception {
        return new DeviceState(DeviceSigningKey.generate(keyType));
    }

    public DeviceSigningKey signingKey() {
        return key;
    }

    public void updateKey(DeviceSigningKey newKey) {
        this.key = newKey;
    }

    public String deviceId() {
        return deviceId;
    }

    public String credentialId() {
        return credentialId;
    }

    public String pushProviderId() {
        return pushProviderId;
    }

    public String pushProviderType() {
        return pushProviderType;
    }

    public void updatePushProvider(String pushProviderId, String pushProviderType) {
        this.pushProviderId = pushProviderId;
        this.pushProviderType = pushProviderType;
    }

    public String deviceLabel() {
        return deviceLabel;
    }

    public String userId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
