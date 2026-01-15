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

package de.arbeitsagentur.keycloak.push.spi;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import de.arbeitsagentur.keycloak.push.util.TokenLogHelper;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

final class LoggingPushNotificationSender implements PushNotificationSender {

    private static final Logger LOG = Logger.getLogger(LoggingPushNotificationSender.class);

    @Override
    public void send(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            String confirmToken,
            String credentialId,
            String challengeId,
            String pushProviderId,
            String clientId) {
        LOG.infof(
                "Simulated push {realm=%s,user=%s,version=%d,type=%d,credentialId=%s,challengeId=%s,pushProviderId=%s,clientId=%s}",
                realm.getName(),
                user.getUsername(),
                PushMfaConstants.PUSH_MESSAGE_VERSION,
                PushMfaConstants.PUSH_MESSAGE_TYPE,
                credentialId,
                challengeId,
                pushProviderId,
                clientId);
        TokenLogHelper.logJwt("confirm-token", confirmToken);
    }

    @Override
    public void close() {
        // no-op
    }
}
