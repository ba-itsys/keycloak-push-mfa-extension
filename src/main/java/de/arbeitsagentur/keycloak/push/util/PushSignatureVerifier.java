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

import jakarta.ws.rs.BadRequestException;
import java.nio.charset.StandardCharsets;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.crypto.ECDSASignatureVerifierContext;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;

public final class PushSignatureVerifier {

    private PushSignatureVerifier() {}

    public static boolean verify(JWSInput input, KeyWrapper keyWrapper) {
        SignatureVerifierContext verifier = context(keyWrapper);
        byte[] data = input.getEncodedSignatureInput().getBytes(StandardCharsets.US_ASCII);
        try {
            return verifier.verify(data, input.getSignature());
        } catch (VerificationException ex) {
            throw new BadRequestException("Unable to verify signature", ex);
        }
    }

    private static SignatureVerifierContext context(KeyWrapper keyWrapper) {
        if (keyWrapper == null || keyWrapper.getType() == null) {
            throw new BadRequestException("JWK missing key type");
        }
        if (KeyType.RSA.equals(keyWrapper.getType())) {
            return new AsymmetricSignatureVerifierContext(keyWrapper);
        }
        if (KeyType.EC.equals(keyWrapper.getType())) {
            return new ECDSASignatureVerifierContext(keyWrapper);
        }
        throw new BadRequestException("Unsupported key type: " + keyWrapper.getType());
    }
}
