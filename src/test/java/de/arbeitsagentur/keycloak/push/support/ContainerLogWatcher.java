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
