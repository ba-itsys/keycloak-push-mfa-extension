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

import org.testcontainers.utility.DockerImageName;

public final class KeycloakContainerImageSupport {

    private static final String DEFAULT_KEYCLOAK_VERSION = "26.5.4";
    private static final String DEFAULT_KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak";

    private KeycloakContainerImageSupport() {}

    public static DockerImageName imageName() {
        return DockerImageName.parse(System.getProperty("test.keycloak.image", defaultImage()));
    }

    private static String defaultImage() {
        return DEFAULT_KEYCLOAK_IMAGE + ":" + System.getProperty("test.keycloak.version", DEFAULT_KEYCLOAK_VERSION);
    }
}
