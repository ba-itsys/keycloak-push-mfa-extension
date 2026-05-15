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
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

public final class KeycloakTestContainerSupport {

    private static final Path EXTENSION_JAR = locateProviderJar();
    private static final Path REALM_FILE =
            Paths.get("config", "demo-realm.json").toAbsolutePath();
    private static final Duration STARTUP_TIMEOUT = Duration.ofMinutes(10);
    private static final String START_COMMAND =
            "start-dev --hostname=localhost --hostname-strict=false --http-enabled=true --import-realm --features=dpop";

    private KeycloakTestContainerSupport() {}

    public static GenericContainer<?> newKeycloakContainer(String execFileName) {
        return newKeycloakContainer(execFileName, null);
    }

    public static GenericContainer<?> newKeycloakContainer(
            String execFileName, Network network, String... networkAliases) {
        try {
            GenericContainer<?> container = new GenericContainer<>(KeycloakContainerImageSupport.image())
                    .withExposedPorts(8080)
                    .withCopyFileToContainer(
                            MountableFile.forHostPath(EXTENSION_JAR), "/opt/keycloak/providers/keycloak-push-mfa.jar")
                    .withCopyFileToContainer(
                            MountableFile.forHostPath(REALM_FILE), "/opt/keycloak/data/import/demo-realm.json")
                    .withEnv("KEYCLOAK_ADMIN", "admin")
                    .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                    .withCommand(START_COMMAND)
                    .waitingFor(Wait.forHttp("/realms/master").forStatusCode(200))
                    .withStartupTimeout(STARTUP_TIMEOUT);
            if (network != null) {
                container.withNetwork(network);
                if (networkAliases.length > 0) {
                    container.withNetworkAliases(networkAliases);
                }
            }
            return instrument(container, execFileName);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to configure Keycloak test container", ex);
        }
    }

    public static URI baseUri(GenericContainer<?> keycloak) {
        return URI.create(String.format("http://%s:%d/", keycloak.getHost(), keycloak.getMappedPort(8080)));
    }

    private static Path locateProviderJar() {
        Path candidate = Paths.get("target", "keycloak-push-mfa-extension.jar").toAbsolutePath();
        if (Files.isRegularFile(candidate)) {
            return candidate;
        }
        throw new IllegalStateException(
                "Provider JAR not found at " + candidate + ". Run mvn package before integration tests.");
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static GenericContainer<?> instrument(GenericContainer<?> container, String execFileName) throws Exception {
        return JacocoContainerSupport.instrumentKeycloakContainer((GenericContainer) container, execFileName);
    }
}
