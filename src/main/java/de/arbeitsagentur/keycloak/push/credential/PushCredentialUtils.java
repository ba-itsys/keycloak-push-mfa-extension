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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import org.keycloak.util.JsonSerialization;

public final class PushCredentialUtils {

    private PushCredentialUtils() {}

    private static ObjectMapper mapper() {
        return JsonSerialization.mapper;
    }

    public static String toJson(PushCredentialData data) {
        try {
            return mapper().writeValueAsString(data);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Unable to serialize push credential data", ex);
        }
    }

    public static PushCredentialData fromJson(String json) {
        try {
            return mapper().readValue(json, PushCredentialData.class);
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to deserialize push credential data", ex);
        }
    }
}
