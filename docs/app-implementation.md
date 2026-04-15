# Mobile App Implementation Notes

This guide covers what mobile app developers need to know when implementing push MFA support.

## Key Concepts

- **Realm verification:** Enrollment starts when the app scans the QR code. Depending on configuration it will receive either a direct `token` value or a `request_uri`. If a `request_uri` is present, fetch that URI over HTTPS first and treat the response body as the `enrollmentToken`. That fetch is bearer-style and does not use DPoP; possession of the `request_uri` is what authorizes it. In both cases, verify the JWT with the realm JWKS (`/realms/<realm>/protocol/openid-connect/certs`) before trusting its contents.
- **User key material:** Generate a key pair per user (or per device if you let a user enroll more than one), select a unique `kid`, and keep the private key in secure storage. Persist and exchange the public component exclusively as a JWK (the same document posted in `cnf.jwk`). With a single device per user you can reuse a stable `deviceId`; only multi-device setups need distinct ids.
- **Algorithm choice:** The demo scripts default to RSA/RS256 but also support EC keys and ECDSA proofs—set `DEVICE_KEY_TYPE=EC`, pick a curve via `DEVICE_EC_CURVE` (P-256/384/521), and override `DEVICE_SIGNING_ALG` if you need ES256/384/512. The selected algorithm lives in the stored JWK (no extra `algorithm` property is stored or sent) so Keycloak enforces it for all future DPoP proofs, login approvals, and rotation requests.

## State to Store Locally

Your app should persist the following:

- Credential ID ↔ real Keycloak user ID mapping
- The user key pair (private key in secure storage)
- The `kid` (key identifier)
- `deviceType` (e.g., "ios", "android")
- `pushProviderId` (FCM/APNs token)
- `pushProviderType` (e.g., "fcm", "apns", "log", "none")
- Preferred `deviceLabel`
- Any metadata needed to post to Keycloak again
- Track a `deviceId` only when you support multiple devices per user

## Confirm Token Handling

When the confirm token arrives through Firebase (or when the user copies it from the waiting UI):

1. Decode the JWT
2. Extract `cid` and `credId`
3. Call `/push-mfa/login/pending` to load user-facing metadata (username + client id/name) before prompting the user
4. If the response contains `userVerification`, implement the requested UX (number match / PIN) and include `userVerification` in the signed approval JWT

## Pending Challenge Discovery

Before calling `/push-mfa/login/pending`, build a DPoP proof that includes:

- HTTP method (`htm`)
- Request URL without query and fragment (`htu`, per [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449#section-4.2))
- `sub` (Keycloak user ID)
- `deviceId`
- `iat` (issued at timestamp)
- A fresh `jti` (unique identifier)

Send it via the `DPoP` header so Keycloak can scope the response to that physical device. The response lists each pending challenge with `clientId`, `clientName`, and `username` (plus optional `userVerification` instructions) that should be shown to the user alongside the approve/deny UI.

## Access Tokens

Obtain a short-lived access token via the realm's token endpoint using the device client credentials. The token request itself must include a DPoP proof, and each subsequent authenticated REST call must send `Authorization: DPoP <access-token>` alongside a fresh `DPoP` header signed with the same key. Enrollment completion uses the same default. You can disable that with `spi-push-mfa--default--dpop-require-for-enrollment=false` for backward compatibility.

## Request Authentication

Every authenticated device REST call must include a DPoP proof signed with the current user key. The only exception in this flow is the optional `request_uri` fetch used by by-reference enrollment, which is a capability URL and does not use DPoP. The proof binds the request method and URL to the hardware-backed key, making replay or reverse-engineering of a shared client secret ineffective.

## Error Handling

Enrollment and login requests return structured error responses (`400`, `403`, or `404`) when the JWTs are invalid, expired, or mismatched. Surface those errors to the user to re-trigger the flow if necessary.

## Key Rotation / Push Provider Changes

Use the `/device/push-provider` and `/device/rotate-key` endpoints (see [API Reference](api-reference.md)) to update the stored metadata while authenticating with the current user key. If the OS disables push notifications or revokes the current push token, switch the credential to `pushProviderType=none` so Keycloak intentionally skips delivery until the app has a working provider again. Rotation should:

1. Generate a fresh key pair
2. Send the new public JWK (with the desired `alg`)
3. Immediately start using the new key for every subsequent JWT
