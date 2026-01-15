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

package de.arbeitsagentur.keycloak.push.util;

import java.io.IOException;
import java.util.Base64;
import org.jboss.logging.Logger;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

public final class TokenLogHelper {

    private static final Logger LOG = Logger.getLogger(TokenLogHelper.class);

    private TokenLogHelper() {}

    public static void logJwt(String label, String token) {
        if (!LOG.isDebugEnabled()) {
            return;
        }
        if (StringUtil.isBlank(token)) {
            LOG.debugf("%s token: <empty>", label);
            return;
        }

        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            LOG.debugf("%s token (non-JWT): %s", label, token);
            return;
        }

        try {
            String headerJson = decodePart(parts[0]);
            String payloadJson = decodePart(parts[1]);
            LOG.debugf("%s token:%n  header:%n%s%n  payload:%n%s", label, indent(headerJson), indent(payloadJson));
        } catch (Exception ex) {
            LOG.debugf("%s token (decode error): %s", label, token);
        }
    }

    private static String decodePart(String segment) throws IOException {
        String normalized = segment + "=".repeat((4 - segment.length() % 4) % 4);
        byte[] decoded = Base64.getUrlDecoder().decode(normalized);
        Object json = JsonSerialization.mapper.readTree(decoded);
        return JsonSerialization.mapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
    }

    private static String indent(String json) {
        if (json == null || json.isBlank()) {
            return "    <empty>";
        }
        String padding = "    ";
        String normalized = json.replace("\r\n", "\n");
        return padding + normalized.replace("\n", System.lineSeparator() + padding);
    }
}
