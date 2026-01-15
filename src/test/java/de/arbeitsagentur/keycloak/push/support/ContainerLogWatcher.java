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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;
import org.testcontainers.containers.ContainerState;

public final class ContainerLogWatcher implements TestWatcher {

    @Override
    public void testFailed(ExtensionContext context, Throwable cause) {
        for (ContainerState container : resolveContainers(context)) {
            try {
                System.err.println(label(container) + " logs:\n" + container.getLogs());
            } catch (Exception ex) {
                System.err.println("Failed to read logs for " + label(container) + ": " + ex.getMessage());
            }
        }
    }

    private List<ContainerState> resolveContainers(ExtensionContext context) {
        List<ContainerState> containers = new ArrayList<>();
        Object testInstance = context.getTestInstance().orElse(null);
        for (Field field : context.getRequiredTestClass().getDeclaredFields()) {
            if (!ContainerState.class.isAssignableFrom(field.getType())) {
                continue;
            }
            boolean isStatic = Modifier.isStatic(field.getModifiers());
            Object target = isStatic ? null : testInstance;
            if (!isStatic && target == null) {
                continue;
            }
            try {
                field.setAccessible(true);
                Object value = field.get(target);
                if (value instanceof ContainerState state) {
                    containers.add(state);
                }
            } catch (IllegalAccessException ignored) {
                // ignore inaccessible fields
            }
        }
        return containers;
    }

    private String label(ContainerState container) {
        String id = container.getContainerId();
        return id == null ? "container" : id;
    }
}
