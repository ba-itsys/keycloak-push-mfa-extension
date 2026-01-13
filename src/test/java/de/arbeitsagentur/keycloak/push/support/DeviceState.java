package de.arbeitsagentur.keycloak.push.support;

import java.util.UUID;

public final class DeviceState {

    private DeviceSigningKey key;
    private final String deviceId;
    private final String credentialId;
    private String pushProviderId;
    private String pushProviderType;
    private final String deviceLabel;
    private String userId;

    private DeviceState(DeviceSigningKey key) {
        this(
                key,
                "device-" + UUID.randomUUID(),
                "credential-" + UUID.randomUUID(),
                "Integration Test Device",
                "mock-push-provider",
                "log");
    }

    public DeviceState(
            DeviceSigningKey key,
            String deviceId,
            String credentialId,
            String deviceLabel,
            String pushProviderId,
            String pushProviderType) {
        this.key = key;
        this.deviceId = deviceId;
        this.credentialId = credentialId;
        this.deviceLabel = deviceLabel;
        this.pushProviderId = pushProviderId;
        this.pushProviderType = pushProviderType;
    }

    public static DeviceState create(DeviceKeyType keyType) throws Exception {
        return new DeviceState(DeviceSigningKey.generate(keyType));
    }

    public static DeviceState createWithLabel(DeviceKeyType keyType, String deviceLabel) throws Exception {
        DeviceSigningKey key = DeviceSigningKey.generate(keyType);
        return new DeviceState(
                key,
                "device-" + UUID.randomUUID(),
                "credential-" + UUID.randomUUID(),
                deviceLabel,
                "mock-push-provider",
                "log");
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
