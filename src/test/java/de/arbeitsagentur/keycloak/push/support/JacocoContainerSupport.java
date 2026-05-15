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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;

public final class JacocoContainerSupport {

    private static final String JACOCO_VERSION = "0.8.14";
    private static final String CONTAINER_AGENT_PATH = "/opt/keycloak/providers/jacoco-agent.jar";
    private static final Path HOST_TARGET_DIR = Paths.get("target").toAbsolutePath();
    private static final Path HOST_EXEC_DIR =
            Paths.get("target", "jacoco-container").toAbsolutePath();
    private static final String CONTAINER_TARGET_DIR = "/coverage";
    private static final String CONTAINER_COVERAGE_DIR = CONTAINER_TARGET_DIR + "/jacoco-container";
    private static final String COVERAGE_INCLUDES = "de.arbeitsagentur.keycloak.push.*";

    private JacocoContainerSupport() {}

    public static <T extends GenericContainer<T>> T instrumentKeycloakContainer(T container, String execFileName)
            throws IOException {
        Files.createDirectories(HOST_EXEC_DIR);
        ensureWritableCoverageDirectory(HOST_EXEC_DIR);
        Files.deleteIfExists(HOST_EXEC_DIR.resolve(execFileName));
        return container
                .withCopyFileToContainer(MountableFile.forHostPath(locateAgentJar()), CONTAINER_AGENT_PATH)
                .withFileSystemBind(HOST_TARGET_DIR.toString(), CONTAINER_TARGET_DIR, BindMode.READ_WRITE)
                .withEnv("JAVA_OPTS_APPEND", agentArgument(execFileName));
    }

    private static Path locateAgentJar() {
        Path agentJar = Paths.get(
                        System.getProperty("user.home"),
                        ".m2",
                        "repository",
                        "org",
                        "jacoco",
                        "org.jacoco.agent",
                        JACOCO_VERSION,
                        "org.jacoco.agent-" + JACOCO_VERSION + "-runtime.jar")
                .toAbsolutePath();
        if (!Files.exists(agentJar)) {
            throw new IllegalStateException("JaCoCo agent JAR not found: " + agentJar);
        }
        return agentJar;
    }

    private static String agentArgument(String execFileName) {
        return "-javaagent:"
                + CONTAINER_AGENT_PATH
                + "=destfile="
                + containerExecPath(execFileName)
                + ",append=true,output=file,includes="
                + COVERAGE_INCLUDES;
    }

    private static String containerExecPath(String execFileName) {
        return CONTAINER_COVERAGE_DIR + "/" + execFileName;
    }

    private static void ensureWritableCoverageDirectory(Path directory) throws IOException {
        try {
            Files.setPosixFilePermissions(
                    directory,
                    EnumSet.of(
                            PosixFilePermission.OWNER_READ,
                            PosixFilePermission.OWNER_WRITE,
                            PosixFilePermission.OWNER_EXECUTE,
                            PosixFilePermission.GROUP_READ,
                            PosixFilePermission.GROUP_WRITE,
                            PosixFilePermission.GROUP_EXECUTE,
                            PosixFilePermission.OTHERS_READ,
                            PosixFilePermission.OTHERS_WRITE,
                            PosixFilePermission.OTHERS_EXECUTE));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystems (for example Docker Desktop mounts on macOS) do not support chmod here.
        }
    }
}
