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

package de.arbeitsagentur.keycloak.push.service;

import de.arbeitsagentur.keycloak.push.spi.PushNotificationSender;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.utils.StringUtil;

public final class PushNotificationService {

    private static final Logger LOG = Logger.getLogger(PushNotificationService.class);

    private PushNotificationService() {}

    public static void notifyDevice(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            String clientId,
            String confirmToken,
            String credentialId,
            String challengeId,
            String pushProviderType,
            String pushProviderId) {
        String providerType =
                StringUtil.isBlank(pushProviderType) ? PushMfaConstants.DEFAULT_PUSH_PROVIDER_TYPE : pushProviderType;
        PushNotificationSender sender = session.getProvider(PushNotificationSender.class, providerType);
        if (sender == null) {
            sender = session.getProvider(PushNotificationSender.class);
        }
        if (sender == null) {
            LOG.warnf("No PushNotificationSender provider available for type %s", providerType);
            return;
        }
        sender.send(session, realm, user, confirmToken, credentialId, challengeId, pushProviderId, clientId);
    }
}
