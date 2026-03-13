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

package de.arbeitsagentur.keycloak.push.support;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

public final class SharedKeycloakContainerSupport {

    private static final Path EXTENSION_JAR = locateProviderJar();
    private static final Path REALM_FILE =
            Paths.get("config", "demo-realm.json").toAbsolutePath();
    private static final String JACOCO_EXEC_FILE = "SharedKeycloakIT.exec";
    private static final Network NETWORK = Network.newNetwork();
    private static final GenericContainer<?> KEYCLOAK = instrumentedKeycloakContainer();

    private static boolean started;
    private static final Set<String> ACTIVE_OWNERS = new HashSet<>();

    private SharedKeycloakContainerSupport() {}

    public static GenericContainer<?> container() {
        return KEYCLOAK;
    }

    public static synchronized void acquire(String owner) throws Exception {
        start();
        ACTIVE_OWNERS.add(owner);
    }

    public static synchronized URI baseUri() throws Exception {
        start();
        return URI.create(String.format("http://%s:%d/", KEYCLOAK.getHost(), KEYCLOAK.getMappedPort(8080)));
    }

    public static Network network() {
        return NETWORK;
    }

    public static synchronized void release(String owner) throws Exception {
        ACTIVE_OWNERS.remove(owner);
        if (!ACTIVE_OWNERS.isEmpty() || !started) {
            return;
        }
        KEYCLOAK.stop();
        NETWORK.close();
        started = false;
    }

    private static void start() throws Exception {
        if (started) {
            return;
        }
        KEYCLOAK.start();
        KeycloakAdminBootstrap.allowHttpAdminLogin(KEYCLOAK);
        started = true;
    }

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
                    new GenericContainer<>("quay.io/keycloak/keycloak:26.4.5")
                            .withNetwork(NETWORK)
                            .withNetworkAliases("keycloak")
                            .withExposedPorts(8080)
                            .withCopyFileToContainer(
                                    MountableFile.forHostPath(EXTENSION_JAR),
                                    "/opt/keycloak/providers/keycloak-push-mfa.jar")
                            .withCopyFileToContainer(
                                    MountableFile.forHostPath(REALM_FILE), "/opt/keycloak/data/import/demo-realm.json")
                            .withEnv("KEYCLOAK_ADMIN", "admin")
                            .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                            .withCommand(
                                    "start-dev --hostname=localhost --hostname-strict=false --http-enabled=true --import-realm --features=dpop")
                            .waitingFor(Wait.forHttp("/realms/master").forStatusCode(200))
                            .withStartupTimeout(Duration.ofMinutes(5)),
                    JACOCO_EXEC_FILE);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to configure shared Keycloak coverage", ex);
        }
    }
}
