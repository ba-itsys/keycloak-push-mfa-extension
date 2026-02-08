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

package de.arbeitsagentur.keycloak.push.credential;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import org.keycloak.utils.StringUtil;

/**
 * Credential data stored with each Push MFA credential.
 *
 * <p>This class holds the device-provided data that was submitted during enrollment, including the
 * device's public key (JWK), push provider details, and the device credential ID.
 *
 * <p><strong>Credential ID distinction:</strong> Each Push MFA credential has two IDs:
 * <ul>
 *   <li>{@code deviceCredentialId} (this class) - chosen by the device during enrollment and used
 *       in tokens, events, and push notifications. The mobile app uses this ID to match incoming
 *       push messages to its local credentials.</li>
 *   <li>{@code keycloakCredentialId} (on {@link de.arbeitsagentur.keycloak.push.challenge.PushChallenge})
 *       - the UUID assigned by Keycloak's credential storage. Used internally to load the
 *       {@code CredentialModel} from the store. The server picks which credential to use for a
 *       challenge and stores this ID; the app never needs to know it.</li>
 * </ul>
 *
 * <p>The JSON property name {@code "credentialId"} is kept for backward compatibility with
 * existing stored credentials.
 */
public class PushCredentialData {

    private final String publicKeyJwk;
    private final long createdAt;
    private final String deviceType;
    private final String pushProviderId;
    private final String pushProviderType;
    private final String deviceCredentialId;
    private final String deviceId;

    @JsonCreator
    public PushCredentialData(
            @JsonProperty("publicKeyJwk") String publicKeyJwk,
            @JsonProperty("createdAt") long createdAt,
            @JsonProperty("deviceType") String deviceType,
            @JsonProperty("pushProviderId") String pushProviderId,
            @JsonProperty("pushProviderType") String pushProviderType,
            @JsonProperty("credentialId") String deviceCredentialId,
            @JsonProperty("deviceId") String deviceId) {
        this.publicKeyJwk = publicKeyJwk;
        this.createdAt = createdAt;
        this.deviceType = deviceType;
        this.pushProviderId = pushProviderId;
        this.pushProviderType =
                StringUtil.isBlank(pushProviderType) ? PushMfaConstants.DEFAULT_PUSH_PROVIDER_TYPE : pushProviderType;
        this.deviceCredentialId = deviceCredentialId;
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

    /**
     * Returns the device-chosen credential ID, set during enrollment.
     *
     * <p>This is NOT the Keycloak-internal credential UUID. See the class-level Javadoc for the
     * distinction between the two credential IDs.
     */
    @JsonProperty("credentialId")
    public String getDeviceCredentialId() {
        return deviceCredentialId;
    }

    public String getDeviceId() {
        return deviceId;
    }
}
