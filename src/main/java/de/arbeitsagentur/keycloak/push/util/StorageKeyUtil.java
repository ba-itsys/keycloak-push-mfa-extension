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

package de.arbeitsagentur.keycloak.push.util;

/**
 * Utility for constructing collision-resistant storage keys.
 *
 * <p>This class uses length-prefixed encoding to prevent key collisions when
 * concatenating multiple variable-length components. Without length prefixing,
 * keys like {@code prefix:realm:user:id} are ambiguous - they could represent
 * {@code realm="realm", userId="user:id"} or {@code realm="realm:user", userId="id"}.
 *
 * <p>With length-prefixed encoding:
 * <ul>
 *   <li>{@code realm="realm", userId="user:id"} → {@code prefix:5:realm:user:id}</li>
 *   <li>{@code realm="realm:user", userId="id"} → {@code prefix:10:realm:user:id}</li>
 * </ul>
 *
 * <p>This is particularly important for customers using custom IDs like URNs
 * (e.g., {@code urn:x:y:uuid}) which contain colons.
 */
public final class StorageKeyUtil {

    private StorageKeyUtil() {
        // utility class
    }

    /**
     * Builds a storage key with length-prefixed encoding for the first component.
     *
     * <p>The format is: {@code prefix + len(component1) + ":" + component1 + ":" + component2}
     *
     * <p>This ensures that the boundary between component1 and component2 is unambiguous,
     * regardless of what characters appear in either component.
     *
     * <p><strong>When to use length-prefixed encoding</strong>
     * <p>Use this utility when concatenating <em>multiple variable-length components</em>
     * that may contain the delimiter character (typically colon). Common scenarios:
     * <ul>
     *   <li>Combining realmId + userId (URNs like {@code urn:x:y:uuid} contain colons)</li>
     *   <li>Combining realmId + jkt + jti (JWK thumbprints and JTIs may vary in format)</li>
     * </ul>
     *
     * <p>You do <em>not</em> need length-prefixed encoding when:
     * <ul>
     *   <li>There is only a single variable component (e.g., {@code prefix + challengeId})</li>
     *   <li>All components are guaranteed to be fixed-length or delimiter-free (e.g., UUIDs)</li>
     * </ul>
     *
     * @param prefix the key prefix (e.g., "push-mfa:wait-state:")
     * @param component1 the first variable component (e.g., realmId)
     * @param component2 the second variable component (e.g., userId)
     * @return a collision-resistant storage key
     */
    public static String buildKey(String prefix, String component1, String component2) {
        // Format: prefix + len(component1) + ":" + component1 + ":" + component2
        // The length prefix tells us exactly where component1 ends, making parsing unambiguous
        return prefix + component1.length() + ":" + component1 + ":" + component2;
    }

    /**
     * Builds a storage key with length-prefixed encoding for three variable components.
     *
     * <p>The format is:
     * {@code prefix + len(component1) + ":" + component1 + ":" + len(component2) + ":" + component2 + ":" + component3}
     *
     * <p>This ensures that boundaries between all components are unambiguous. The last
     * component does not need length-prefixing since it extends to the end of the key.
     *
     * @param prefix the key prefix (e.g., "push-mfa:dpop:jti:")
     * @param component1 the first variable component (e.g., realmId)
     * @param component2 the second variable component (e.g., jkt)
     * @param component3 the third variable component (e.g., jti)
     * @return a collision-resistant storage key
     */
    public static String buildKey(String prefix, String component1, String component2, String component3) {
        // Format: prefix + len(c1) + ":" + c1 + ":" + len(c2) + ":" + c2 + ":" + c3
        // Length prefixes for c1 and c2 make all boundaries unambiguous
        return prefix + component1.length() + ":" + component1 + ":" + component2.length() + ":" + component2 + ":"
                + component3;
    }
}
