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

import java.util.HashMap;
import java.util.Map;
import org.keycloak.models.SingleUseObjectProvider;

public final class InMemorySingleUseObjectProvider implements SingleUseObjectProvider {

    private final Map<String, Map<String, String>> data = new HashMap<>();

    @Override
    public void put(String key, long lifespanSeconds, Map<String, String> value) {
        data.put(key, new HashMap<>(value));
    }

    @Override
    public Map<String, String> get(String key) {
        Map<String, String> value = data.get(key);
        return value == null ? null : new HashMap<>(value);
    }

    @Override
    public Map<String, String> remove(String key) {
        Map<String, String> removed = data.remove(key);
        return removed == null ? null : new HashMap<>(removed);
    }

    @Override
    public boolean replace(String key, Map<String, String> value) {
        if (!data.containsKey(key)) {
            return false;
        }
        data.put(key, new HashMap<>(value));
        return true;
    }

    @Override
    public boolean putIfAbsent(String key, long lifespanSeconds) {
        if (data.containsKey(key)) {
            return false;
        }
        data.put(key, new HashMap<>());
        return true;
    }

    @Override
    public boolean contains(String key) {
        return data.containsKey(key);
    }

    @Override
    public void close() {
        // no-op
    }
}
