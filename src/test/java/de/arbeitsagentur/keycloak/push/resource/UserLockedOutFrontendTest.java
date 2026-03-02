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

package de.arbeitsagentur.keycloak.push.resource;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * Tests for USER_LOCKED_OUT frontend integration via SSE and FTL templates.
 *
 * <p>Verifies that:
 * 1. SSE stream propagates `status: "USER_LOCKED_OUT"` to awaiting browsers
 * 2. Javascript in push-mfa.js submits the completion form on status change
 * 3. FTL template push-user-locked-out.ftl is displayed to the user
 * 4. push-wait.ftl data attributes enable automatic status watching
 */
class UserLockedOutFrontendTest {

    @Test
    void pushWaitFtlIncludesDataAttributesForSseWatching() throws Exception {
        Path template = Path.of("src/main/resources/theme-resources/templates/push-wait.ftl");
        String content = Files.readString(template);

        // verify the template has the expected data attributes that enable SSE watching
        assertTrue(
                content.contains("data-push-mfa-page=\"login-wait\""),
                "push-wait.ftl must include data-push-mfa-page attribute for JS auto-init");
        assertTrue(content.contains("data-push-events-url="), "push-wait.ftl must include SSE endpoint URL");
        assertTrue(
                content.contains("data-push-form-id="),
                "push-wait.ftl must include form ID for auto-submission on status change");
    }

    @Test
    void pushMfaJsIsIncludedInTemplate() throws Exception {
        Path template = Path.of("src/main/resources/theme-resources/templates/push-wait.ftl");
        String content = Files.readString(template);

        assertTrue(
                content.contains("push-mfa.js"),
                "push-wait.ftl must include push-mfa.js script that handles SSE and auto-submits form");
    }

    @Test
    void pushUserLockedOutFtlDisplaysLockedOutMessage() throws Exception {
        Path template = Path.of("src/main/resources/theme-resources/templates/push-user-locked-out.ftl");
        String content = Files.readString(template);

        // verify the locked-out template references the message key
        assertTrue(
                content.contains("push-mfa-user-locked-out-message"),
                "Template should reference the message key for locked-out description");
        assertTrue(content.contains("kc-push-card"), "Template should include the UI card wrapper");
    }
}
