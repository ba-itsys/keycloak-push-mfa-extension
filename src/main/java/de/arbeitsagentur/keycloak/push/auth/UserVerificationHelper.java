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
