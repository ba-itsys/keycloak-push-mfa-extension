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

package de.arbeitsagentur.keycloak.push;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import de.arbeitsagentur.keycloak.push.util.PushMfaKeyUtil;
import jakarta.ws.rs.BadRequestException;
import org.junit.jupiter.api.Test;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;

class PushMfaResourceTest {

    @Test
    void computeThumbprintMatchesNimbusForRsa() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).generate().toPublicJWK();
        String json = rsaKey.toJSONString();
        String expected = rsaKey.computeThumbprint().toString();
        String actual = PushMfaKeyUtil.computeJwkThumbprint(json);
        assertEquals(expected, actual);
    }

    @Test
    void computeThumbprintMatchesNimbusForEc() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate().toPublicJWK();
        String json = ecKey.toJSONString();
        String expected = ecKey.computeThumbprint().toString();
        String actual = PushMfaKeyUtil.computeJwkThumbprint(json);
        assertEquals(expected, actual);
    }

    @Test
    void ensureKeyMatchesRejectsMismatchedAlgorithm() {
        KeyWrapper rsa = new KeyWrapper();
        rsa.setType(KeyType.RSA);
        rsa.setAlgorithm("RS256");
        assertThrows(BadRequestException.class, () -> PushMfaKeyUtil.ensureKeyMatchesAlgorithm(rsa, "ES256"));
    }

    @Test
    void ensureKeyMatchesRejectsCurveMismatch() {
        KeyWrapper ec = new KeyWrapper();
        ec.setType(KeyType.EC);
        ec.setAlgorithm("ES256");
        ec.setCurve("P-384");
        assertThrows(BadRequestException.class, () -> PushMfaKeyUtil.ensureKeyMatchesAlgorithm(ec, "ES256"));
    }
}
