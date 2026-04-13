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

package de.arbeitsagentur.keycloak.push.spi.pushnotification;

import de.arbeitsagentur.keycloak.push.spi.PushNotificationSender;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

final class NoOpPushNotificationSender implements PushNotificationSender {

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
        // Intentionally do nothing. This provider allows clients to disable
        // push delivery temporarily without producing missing-provider errors.
    }

    @Override
    public void close() {
        // no-op
    }
}
