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

package de.arbeitsagentur.keycloak.push.auth;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.stream.IntStream;

/** Helper for generating user verification values (number match, PIN). */
public final class UserVerificationHelper {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final List<String> NUMBER_MATCH_VALUES =
            IntStream.range(0, 100).mapToObj(String::valueOf).toList();

    private UserVerificationHelper() {}

    public static List<String> generateNumberMatchOptions() {
        List<String> values = new ArrayList<>(NUMBER_MATCH_VALUES);
        Collections.shuffle(values, RANDOM);
        return List.copyOf(values.subList(0, 3));
    }

    public static String selectNumberMatchValue(List<String> options) {
        if (options == null || options.isEmpty()) {
            return null;
        }
        return options.get(RANDOM.nextInt(options.size()));
    }

    public static String generatePin(int length) {
        return generatePin(length, RANDOM);
    }

    public static String generatePin(int length, Random random) {
        int effectiveLength = Math.max(1, length);
        StringBuilder builder = new StringBuilder(effectiveLength);
        for (int i = 0; i < effectiveLength; i++) {
            builder.append(random.nextInt(10));
        }
        return builder.toString();
    }
}
