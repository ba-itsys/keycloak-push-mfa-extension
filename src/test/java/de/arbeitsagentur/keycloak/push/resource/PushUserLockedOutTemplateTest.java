package de.arbeitsagentur.keycloak.push.resource;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class PushUserLockedOutTemplateTest {
    @Test
    void pushUserLockedOutFtlContainsMessageKey() throws Exception {
        Path template = Path.of("src/main/resources/theme-resources/templates/push-user-locked-out.ftl");
        String content = Files.readString(template);
        assertTrue(
                content.contains("push-mfa-user-locked-out-message"),
                "Template should reference the message key for locked-out description");
        assertTrue(content.contains("kc-push-card"), "Template should include the UI card wrapper");
    }
}
