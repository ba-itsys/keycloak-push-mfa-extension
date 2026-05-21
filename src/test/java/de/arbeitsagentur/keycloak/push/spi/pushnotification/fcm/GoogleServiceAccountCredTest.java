package de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mockStatic;

import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.model.GoogleServiceAccountCred;
import de.arbeitsagentur.keycloak.push.spi.pushnotification.fcm.util.ConfigUtil;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

public class GoogleServiceAccountCredTest {
    @Test
    public void testLoadFromFile() {
        String privateKeyStr =
                "-----BEGIN PRIVATE KEY-----MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDQEASGgLNJtxMZRCxCLx2n30FM\r\nxvzyIwleQgwjz7Ut9hQe+l5Z5cEjpNJ+UA6idEcIukQfTIfZZ8CuRcnDT0eCTZiIVRkDopXApz1O\r\n3ZDbme1y4YbJ2nYtO8+WTcBYQkNMJDI+A4AhGX52LbIGkXK6i8prBoISN/2yJiindhsy4Zxe4FAw\r\n0HbK/LBhGkqZ/1C2PO1B+fdYjM9GXaA+Vs33evbQDibwRqWs1TgJJNU2BAWaWXSMN/WWNjwpQ38s\r\nbYBxSTv5Nw/hsldcJqcMlS2QtCEb4VaN5rcfJPqFRIVZ8AInrS+RZY7k1wTSa+C4wUWthCrK+2hP\r\nqMqsZSqqM02VAgMBAAECggEAIIbYhkR5guUtha4sMx6Vhsh2t2+GXL5QeR1fM3wFyY0mYR9n/6rU\r\n8mMSiy+t0gTWlA02mCQJOtom+7eqTq/GsJ674VhYZEKXIbqjcYBe5I3gWqzaOxU9k1292rQGBWY6\r\nih1Ag4RdlA8dv5DuO2uioXo4J1opnHqHXUHs6h0jLGVjnSFxERAyBW0vE7fqbTlPVXUK1SacZmw8\r\nGmd1NofaEMuq+rpQ4Rh8DQphuYGWNYcrBhfO47RKDmUKuD8gpf8NYpu3DcUCIFzbh69ACtxFzax5\r\nC/I1NJQzRMhUIkNmOvT2b9nIC70mc7TMbJS86mo/Fl3yJXKO+LQvdAepVfRGowKBgQDz3PlNOYcs\r\n5aY3xS8VkIAlWxgeIUWn9qmXcjK/V3+QXDB24/+PqZ5ufOAu4VRE/cuKQTOQ4bog5Z13hUmzG4Zy\r\nkcMz0QHpkG1rndxvhZ7px6Va6rv2BVlQy9ajxtDfIW5xfaVC0JLukPeI8mfI3vm/2j9jXluXqM05\r\nT9h0nJ8zMwKBgQDaaunRUUgJhwIg+8re9HCM/zVxYsH9LPmhYZClW+a63FNDW3PIrTr7qy4fm9g3\r\nY7NKIXHS7+mKnM4Px8w/zP8bUwvn6YorSwKvIyda3jHaixJUSu0A6kPEoAzDfuj5VGYYUiw1Oe2F\r\nAiXq9LacIDZmkHD0dx0P8uAciAkymIN8FwKBgQDru5hixlGdXQGot7wkJGM7uSs/NPqYuyCFfacA\r\nwBxX+EYBJ7VLsrOsKpqrtrY3Wv7+zriCPTInys7FUttDgEAfUDhaRpiKp0qe1SLZy1kqtAtsL60y\r\nzUjhiaoa933BtBeHLeYrCGSAqTIf9/PLgX/7rYXJENWJbWu1EzIyx5Q9cQKBgQCizeJvRZjekSXD\r\nFCwJuEZUsr5RP/29C1MfOawptbDsQ+JEaNyLDqTShqwgn3exAb3YWcmQI4f+7BakqJbUT6cv5N0R\r\nBoEY+BaOGTPyhYC/l74X2qmCbxwIagxZhDV/86sOIeIV4pHq/Mjqs3GSOmiSVsP7VPXyt2TZn4TL\r\nk+ceDQKBgQDhSLCeJbDRGKfK9Le9Qe6oleAlBlWfvWPx4WqBBcyrrJc48Ph9kbC4SQAgE57dxtl7\r\ngINomBRaRmgt0PlO9fq7y6hEZ0mYCd2SZHUaQcwQQBYPYoz7frrGAeEeP26pKIQ7ganvRFFtnhj5\r\nGmNXbciCOUSB+OQfcF4frrd7r3bvzg==-----END PRIVATE KEY-----";

        try (MockedStatic<ConfigUtil> mockedConfigUtil = mockStatic(ConfigUtil.class)) {
            mockedConfigUtil
                    .when(() -> ConfigUtil.getEnvString("GOOGLE_APPLICATION_CREDENTIALS"))
                    .thenReturn("mock/mock-google-credentials.json");

            GoogleServiceAccountCred cred = GoogleServiceAccountCred.loadFromFile();
            assertNotNull(cred);
            assertEquals("ba-secure-mock", cred.getProjectId());
            assertEquals("fcm-mock@test.de", cred.getClientEmail());
            assertEquals("some_key_id", cred.getPrivateKeyId());
            assertEquals("service_account", cred.getType());
            assertEquals(privateKeyStr, cred.getPrivateKey());
        }
    }

    @Test
    public void testLoadFromFileNoFile() {
        try (MockedStatic<ConfigUtil> mockedConfigUtil = mockStatic(ConfigUtil.class)) {
            mockedConfigUtil
                    .when(() -> ConfigUtil.getEnvString("GOOGLE_APPLICATION_CREDENTIALS"))
                    .thenReturn("mock/not-found.json");

            GoogleServiceAccountCred cred = GoogleServiceAccountCred.loadFromFile();
            assertNull(cred);
        }
    }

    @Test
    public void testLoadFromFileNoEnv() {
        try (MockedStatic<ConfigUtil> mockedConfigUtil = mockStatic(ConfigUtil.class)) {
            mockedConfigUtil
                    .when(() -> ConfigUtil.getEnvString("GOOGLE_APPLICATION_CREDENTIALS"))
                    .thenReturn(null);

            GoogleServiceAccountCred cred = GoogleServiceAccountCred.loadFromFile();
            assertNull(cred);
        }
    }
}
