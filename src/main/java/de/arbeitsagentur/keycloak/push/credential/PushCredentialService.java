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

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.util.List;
import java.util.stream.Collectors;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.utils.StringUtil;

public final class PushCredentialService {

    private PushCredentialService() {}

    public static List<CredentialModel> getActiveCredentials(UserModel user) {
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(PushMfaConstants.CREDENTIAL_TYPE)
                .collect(Collectors.toList());
    }

    public static CredentialModel createCredential(UserModel user, String label, PushCredentialData data) {
        CredentialModel model = new CredentialModel();
        model.setType(PushMfaConstants.CREDENTIAL_TYPE);
        model.setUserLabel(label);
        model.setCredentialData(PushCredentialUtils.toJson(data));
        model.setSecretData("{}");
        model.setCreatedDate(System.currentTimeMillis());
        SubjectCredentialManager manager = user.credentialManager();
        return manager.createStoredCredential(model);
    }

    public static PushCredentialData readCredentialData(CredentialModel credentialModel) {
        return PushCredentialUtils.fromJson(credentialModel.getCredentialData());
    }

    public static void updateCredential(UserModel user, CredentialModel credential, PushCredentialData data) {
        credential.setCredentialData(PushCredentialUtils.toJson(data));
        user.credentialManager().updateStoredCredential(credential);
    }

    public static CredentialModel getCredentialById(UserModel user, String credentialId) {
        if (StringUtil.isBlank(credentialId)) {
            return null;
        }
        CredentialModel model = user.credentialManager().getStoredCredentialById(credentialId);
        if (model == null || !PushMfaConstants.CREDENTIAL_TYPE.equals(model.getType())) {
            return null;
        }
        return model;
    }
}
