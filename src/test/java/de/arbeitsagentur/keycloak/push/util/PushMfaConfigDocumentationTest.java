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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PushMfaConfigDocumentationTest {

    @Test
    void configurationDocsMatchCodeMetadata() throws Exception {
        Map<String, DocRow> documentedRows = parseDocumentationTable();

        assertEquals(PushMfaConfig.documentation().size(), documentedRows.size());
        for (PushMfaConfig.ConfigDocumentation config : PushMfaConfig.documentation()) {
            DocRow documented = documentedRows.get(config.key());
            assertNotNull(documented, () -> "Missing docs row for " + config.key());
            assertEquals(
                    config.defaultValue(), documented.defaultValue(), () -> "Default mismatch for " + config.key());
            assertEquals(config.range(), documented.range(), () -> "Range mismatch for " + config.key());
        }
    }

    private static Map<String, DocRow> parseDocumentationTable() throws Exception {
        Map<String, DocRow> rows = new LinkedHashMap<>();
        for (String line : Files.readAllLines(Path.of("docs", "configuration.md"))) {
            if (!line.startsWith("| `spi-push-mfa--default--")) {
                continue;
            }
            String[] columns = line.split("\\|");
            if (columns.length < 4) {
                continue;
            }
            String key = normalize(columns[1]).replace("spi-push-mfa--default--", "");
            String defaultValue = normalize(columns[2]);
            String range = normalize(columns[3]);
            rows.put(key, new DocRow(defaultValue, range));
        }
        return rows;
    }

    private static String normalize(String value) {
        return value.replace("`", "").replace(" ", "").trim();
    }

    private record DocRow(String defaultValue, String range) {}
}
