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

import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;

public final class KeycloakAdminBootstrap {

    private KeycloakAdminBootstrap() {}

    public static void allowHttpAdminLogin(GenericContainer<?> keycloak) throws Exception {
        exec(
                keycloak,
                "/opt/keycloak/bin/kcadm.sh",
                "config",
                "credentials",
                "--server",
                "http://localhost:8080",
                "--realm",
                "master",
                "--user",
                "admin",
                "--password",
                "admin");
        exec(keycloak, "/opt/keycloak/bin/kcadm.sh", "update", "realms/master", "-s", "sslRequired=NONE");
    }

    private static void exec(GenericContainer<?> keycloak, String... command) throws Exception {
        Container.ExecResult result = keycloak.execInContainer(command);
        if (result.getExitCode() != 0) {
            throw new IllegalStateException(
                    "Keycloak bootstrap command failed (" + String.join(" ", command) + "): " + result.getStderr());
        }
    }
}
