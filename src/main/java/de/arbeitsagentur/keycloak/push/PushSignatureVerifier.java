package de.arbeitsagentur.keycloak.push;

import jakarta.ws.rs.BadRequestException;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.crypto.ECDSASignatureVerifierContext;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;

import java.nio.charset.StandardCharsets;

final class PushSignatureVerifier {

    private PushSignatureVerifier() {
    }

    static boolean verify(JWSInput input, KeyWrapper keyWrapper) {
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
