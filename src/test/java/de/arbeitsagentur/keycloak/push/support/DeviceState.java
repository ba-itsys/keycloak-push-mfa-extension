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
