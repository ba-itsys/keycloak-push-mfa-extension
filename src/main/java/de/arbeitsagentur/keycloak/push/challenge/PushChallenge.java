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

package de.arbeitsagentur.keycloak.push.challenge;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public final class PushChallenge {

    public enum Type {
        ENROLLMENT,
        AUTHENTICATION
    }

    public enum UserVerificationMode {
        NONE,
        NUMBER_MATCH,
        PIN
    }

    private final String id;
    private final String realmId;
    private final String userId;
    private final byte[] nonce;
    private final String credentialId;
    private final String clientId;
    private final String watchSecret;
    private final String rootSessionId;
    private final Instant expiresAt;
    private final Type type;
    private final PushChallengeStatus status;
    private final Instant createdAt;
    private final Instant resolvedAt;
    private final UserVerificationMode userVerificationMode;
    private final String userVerificationValue;
    private final List<String> userVerificationOptions;

    public PushChallenge(
            String id,
            String realmId,
            String userId,
            byte[] nonce,
            String credentialId,
            String clientId,
            String watchSecret,
            String rootSessionId,
            Instant expiresAt,
            Type type,
            PushChallengeStatus status,
            Instant createdAt,
            Instant resolvedAt) {
        this(
                id,
                realmId,
                userId,
                nonce,
                credentialId,
                clientId,
                watchSecret,
                rootSessionId,
                expiresAt,
                type,
                status,
                createdAt,
                resolvedAt,
                UserVerificationMode.NONE,
                null,
                List.of());
    }

    public PushChallenge(
            String id,
            String realmId,
            String userId,
            byte[] nonce,
            String credentialId,
            String clientId,
            String watchSecret,
            String rootSessionId,
            Instant expiresAt,
            Type type,
            PushChallengeStatus status,
            Instant createdAt,
            Instant resolvedAt,
            UserVerificationMode userVerificationMode,
            String userVerificationValue,
            List<String> userVerificationOptions) {
        this.id = Objects.requireNonNull(id);
        this.realmId = Objects.requireNonNull(realmId);
        this.userId = Objects.requireNonNull(userId);
        this.nonce = Arrays.copyOf(Objects.requireNonNull(nonce), nonce.length);
        this.credentialId = credentialId;
        this.clientId = clientId;
        this.watchSecret = watchSecret;
        this.rootSessionId = rootSessionId;
        this.expiresAt = Objects.requireNonNull(expiresAt);
        this.type = Objects.requireNonNull(type);
        this.status = Objects.requireNonNull(status);
        this.createdAt = Objects.requireNonNull(createdAt);
        this.resolvedAt = resolvedAt;
        this.userVerificationMode = userVerificationMode == null ? UserVerificationMode.NONE : userVerificationMode;
        this.userVerificationValue = userVerificationValue;
        this.userVerificationOptions =
                userVerificationOptions == null ? List.of() : List.copyOf(userVerificationOptions);
    }

    public String getId() {
        return id;
    }

    public String getRealmId() {
        return realmId;
    }

    public String getUserId() {
        return userId;
    }

    public byte[] getNonce() {
        return Arrays.copyOf(nonce, nonce.length);
    }

    public String getCredentialId() {
        return credentialId;
    }

    public String getClientId() {
        return clientId;
    }

    public String getWatchSecret() {
        return watchSecret;
    }

    public String getRootSessionId() {
        return rootSessionId;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Type getType() {
        return type;
    }

    public PushChallengeStatus getStatus() {
        return status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getResolvedAt() {
        return resolvedAt;
    }

    public UserVerificationMode getUserVerificationMode() {
        return userVerificationMode;
    }

    public String getUserVerificationValue() {
        return userVerificationValue;
    }

    public List<String> getUserVerificationOptions() {
        return userVerificationOptions;
    }
}
