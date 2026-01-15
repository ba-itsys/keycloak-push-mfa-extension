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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.util.UUID;

public final class DeviceSigningKey {

    private final JWK key;
    private final JWSAlgorithm algorithm;
    private final JWSSigner signer;

    private DeviceSigningKey(JWK key, JWSAlgorithm algorithm, JWSSigner signer) {
        this.key = key;
        this.algorithm = algorithm;
        this.signer = signer;
    }

    public static DeviceSigningKey generate(DeviceKeyType type) throws Exception {
        return switch (type) {
            case RSA -> generateRsa();
            case ECDSA -> generateEcdsa();
        };
    }

    public static DeviceSigningKey generateRsa() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyID("user-key-" + UUID.randomUUID())
                .algorithm(JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        return new DeviceSigningKey(rsaKey, JWSAlgorithm.RS256, new RSASSASigner(rsaKey));
    }

    public static DeviceSigningKey generateEcdsa() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256)
                .keyID("user-key-" + UUID.randomUUID())
                .algorithm(JWSAlgorithm.ES256)
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        return new DeviceSigningKey(ecKey, JWSAlgorithm.ES256, new ECDSASigner(ecKey));
    }

    public JWK publicJwk() {
        return key.toPublicJWK();
    }

    public String keyId() {
        return key.getKeyID();
    }

    public JWSSigner signer() {
        return signer;
    }

    public JWSAlgorithm algorithm() {
        return algorithm;
    }
}
