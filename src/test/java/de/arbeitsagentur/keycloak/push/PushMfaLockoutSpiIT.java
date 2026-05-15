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

package de.arbeitsagentur.keycloak.push;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.arbeitsagentur.keycloak.push.it.lockout.TestAttributePushMfaLockoutHandler;
import de.arbeitsagentur.keycloak.push.it.lockout.TestAttributePushMfaLockoutHandlerFactory;
import de.arbeitsagentur.keycloak.push.support.AdminClient;
import de.arbeitsagentur.keycloak.push.support.BrowserSession;
import de.arbeitsagentur.keycloak.push.support.ContainerLogWatcher;
import de.arbeitsagentur.keycloak.push.support.DeviceClient;
import de.arbeitsagentur.keycloak.push.support.DeviceKeyType;
import de.arbeitsagentur.keycloak.push.support.DeviceState;
import de.arbeitsagentur.keycloak.push.support.HtmlPage;
import de.arbeitsagentur.keycloak.push.support.JacocoContainerSupport;
import de.arbeitsagentur.keycloak.push.support.KeycloakAdminBootstrap;
import de.arbeitsagentur.keycloak.push.support.KeycloakContainerImageSupport;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

@Testcontainers
@ExtendWith(ContainerLogWatcher.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PushMfaLockoutSpiIT {

    private static final Path EXTENSION_JAR = locateProviderJar();
    private static final Path LOCKOUT_TEST_PROVIDER_JAR = buildLockoutTestProviderJar();
    private static final Path REALM_FILE =
            Paths.get("config", "demo-realm.json").toAbsolutePath();
    private static final String TEST_USERNAME = "test";
    private static final String TEST_PASSWORD = "test";
    private static final String JACOCO_EXEC_FILE = "PushMfaLockoutSpiIT.exec";

    @Container
    private static final GenericContainer<?> KEYCLOAK = instrumentedKeycloakContainer();

    private URI baseUri;
    private AdminClient adminClient;

    @BeforeAll
    void setup() throws Exception {
        KeycloakAdminBootstrap.allowHttpAdminLogin(KEYCLOAK);
        baseUri = URI.create(String.format("http://%s:%d/", KEYCLOAK.getHost(), KEYCLOAK.getMappedPort(8080)));
        adminClient = new AdminClient(baseUri);
    }

    @BeforeEach
    void resetState() throws Exception {
        adminClient.resetUserState(TEST_USERNAME);
        adminClient.enableUser(TEST_USERNAME);
        adminClient.clearUserAttribute(TEST_USERNAME, TestAttributePushMfaLockoutHandler.LOCKOUT_MARKER_ATTRIBUTE);
    }

    @Test
    void configuredLockoutHandlerOverridesDefaultDisableBehavior() throws Exception {
        DeviceClient deviceClient = enrollDevice();
        assertTrue(adminClient.isUserEnabled(TEST_USERNAME), "User should start enabled");

        String status = deviceClient.lockoutUser();

        assertEquals("locked_out", status);
        assertTrue(adminClient.isUserEnabled(TEST_USERNAME), "Custom handler should keep the user enabled");
        awaitLockoutMarkerLog(
                "clientId=push-device-client deviceId=" + deviceClient.state().deviceId());
    }

    private DeviceClient enrollDevice() throws Exception {
        DeviceState deviceState = DeviceState.create(DeviceKeyType.RSA);
        DeviceClient deviceClient = new DeviceClient(baseUri, deviceState);

        BrowserSession enrollmentSession = new BrowserSession(baseUri);
        HtmlPage loginPage = enrollmentSession.startAuthorization("test-app");
        HtmlPage enrollmentPage = enrollmentSession.submitLogin(loginPage, TEST_USERNAME, TEST_PASSWORD);
        String enrollmentToken = enrollmentSession.extractEnrollmentToken(enrollmentPage);
        deviceClient.completeEnrollment(enrollmentToken);
        enrollmentSession.submitEnrollmentCheck(enrollmentPage);
        return deviceClient;
    }

    private static Path buildLockoutTestProviderJar() {
        try {
            Path targetDir = Paths.get("target", "test-provider-jars").toAbsolutePath();
            Files.createDirectories(targetDir);
            Path jarPath = targetDir.resolve("push-mfa-lockout-test-provider.jar");

            List<String> entries = List.of(
                    "de/arbeitsagentur/keycloak/push/it/lockout/TestAttributePushMfaLockoutHandler.class",
                    "de/arbeitsagentur/keycloak/push/it/lockout/TestAttributePushMfaLockoutHandlerFactory.class",
                    "META-INF/services/de.arbeitsagentur.keycloak.push.spi.PushMfaLockoutHandlerFactory");

            try (OutputStream out = Files.newOutputStream(jarPath);
                    JarOutputStream jar = new JarOutputStream(out)) {
                for (String entry : entries) {
                    Path source = Paths.get("target", "test-classes", entry);
                    if (!Files.isRegularFile(source)) {
                        throw new IllegalStateException("Missing test provider artifact: " + source);
                    }
                    jar.putNextEntry(new JarEntry(entry));
                    Files.copy(source, jar);
                    jar.closeEntry();
                }
            }
            return jarPath;
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to build lockout test provider jar", ex);
        }
    }

    private void awaitLockoutMarkerLog(String markerSuffix) throws Exception {
        String expectedPrefix = TestAttributePushMfaLockoutHandler.LOG_MARKER + " " + markerSuffix;
        long deadline = System.currentTimeMillis() + 5000L;
        while (System.currentTimeMillis() < deadline) {
            if (KEYCLOAK.getLogs().contains(expectedPrefix)) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("Expected lockout handler log marker not found: " + expectedPrefix);
    }

    /**
     * find the fixed JAR produced by Maven
     */
    private static Path locateProviderJar() {
        Path candidate = Paths.get("target", "keycloak-push-mfa-extension.jar").toAbsolutePath();
        if (Files.isRegularFile(candidate)) {
            return candidate;
        }
        throw new IllegalStateException(
                "Provider JAR not found at " + candidate + ". Run mvn package before integration tests.");
    }

    private static GenericContainer<?> instrumentedKeycloakContainer() {
        try {
            return JacocoContainerSupport.instrumentKeycloakContainer(
                    new GenericContainer<>(KeycloakContainerImageSupport.image())
                            .withExposedPorts(8080)
                            .withCopyFileToContainer(
                                    MountableFile.forHostPath(EXTENSION_JAR),
                                    "/opt/keycloak/providers/keycloak-push-mfa.jar")
                            .withCopyFileToContainer(
                                    MountableFile.forHostPath(LOCKOUT_TEST_PROVIDER_JAR),
                                    "/opt/keycloak/providers/push-mfa-lockout-test-provider.jar")
                            .withCopyFileToContainer(
                                    MountableFile.forHostPath(REALM_FILE), "/opt/keycloak/data/import/demo-realm.json")
                            .withEnv("KEYCLOAK_ADMIN", "admin")
                            .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                            .withCommand(
                                    "start-dev --hostname=localhost --hostname-strict=false --http-enabled=true --import-realm --features=dpop --spi-push-mfa-lockout-handler--provider="
                                            + TestAttributePushMfaLockoutHandlerFactory.ID)
                            .waitingFor(Wait.forHttp("/realms/master").forStatusCode(200))
                            .withStartupTimeout(Duration.ofMinutes(10)),
                    JACOCO_EXEC_FILE);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to configure lockout SPI Keycloak coverage", ex);
        }
    }
}
