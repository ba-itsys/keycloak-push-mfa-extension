# API Reference

All endpoints live under `/realms/<realm>/push-mfa`. Enrollment completion posts the device JWT in the request body. The enrollment `request_uri` fetch endpoint is capability-URL based and does not use DPoP. The remaining device-facing endpoints require a DPoP header signed with the user key (see [Flow Details](flow-details.md#dpop-authentication)). Access tokens still come from the device client credentials, but they are DPoP-bound so every authenticated device request is cryptographically tied to the hardware key material.

## Fetch Enrollment Token By Reference

When the required action is configured with `enrollmentUseRequestUri=true`, the QR code and same-device app link no longer embed the full enrollment token directly. Instead they carry a short-lived `request_uri` that points to this endpoint:

```
GET /realms/<realm>/push-mfa/enroll/request-token/{requestHandle}
Accept: application/jwt
```

The response body is the same realm-signed enrollment JWT that would otherwise have been embedded in the QR code directly. The endpoint is intentionally capability-URL based: possession of the random `requestHandle` is what authorizes the fetch. The handle stays valid only while the enrollment challenge is still pending and the handle itself has not expired. Its lifetime defaults to the enrollment challenge lifetime, and can be shortened independently with `enrollmentRequestUriTtlSeconds`.

## Complete Enrollment

```
POST /realms/<realm>/push-mfa/enroll/complete
Content-Type: application/json

{
  "token": "<device-signed enrollment JWT>"
}
```

Keycloak verifies the signature using `cnf.jwk`, persists the credential (JWK, deviceType, `pushProviderId`, `pushProviderType`, credentialId, deviceId, deviceLabel), and resolves the enrollment challenge. The `pushProviderId` value is whatever identifier your push backend requires (for example an FCM registration token or an APNs device token), while `pushProviderType` selects the Keycloak `PushNotificationSender` provider that should deliver the confirm token. The bundled implementations expose `log` (prints the payload) and `none` (intentionally does nothing). If `pushProviderType` is omitted during enrollment, it defaults to `none`; in that case `pushProviderId` is optional as well. Real deployments can plug in any provider via the [Push Notification SPI](spi-reference.md#push-notification-spi). The `deviceLabel` is read from the JWT payload (falls back to `PushMfaConstants.USER_CREDENTIAL_DISPLAY_NAME` when absent).

Enrollment supports optional DPoP-bound auth as a fail-fast check for broken device DPoP generation, usually caused by severe local clock skew. Set `keycloak.push-mfa.dpop.requireForEnrollment=true` to enforce it.

If two completion requests race for the same enrollment challenge, the loser may receive `409 Conflict` with `Challenge is currently being resolved` or `400 Bad Request` with `Challenge already resolved or expired`, depending on whether the competing request is still in-flight or has already finished resolving the challenge.

**Response:**
```json
{
  "status": "enrolled"
}
```

## List Pending Login Challenges

```
GET /realms/<realm>/push-mfa/login/pending?userId=<keycloak-user-id>
Authorization: DPoP <access-token>
DPoP: <proof JWT>
```

The `DPoP` header carries a short-lived JWT signed with the user key (see [DPoP Proof Structure](flow-details.md#dpop-proof-structure)). Its payload must include `htm`, `htu` (request URL without query and fragment per [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449#section-4.2)), `iat`, `jti`, plus the custom `sub` (Keycloak user id) and `deviceId`. Keycloak verifies the signature using the stored credential and only returns pending challenges tied to that device id.

**Response:**
```json
{
  "challenges": [
    {
      "userId": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
      "username": "test",
      "cid": "1a6d6a0b-3385-4772-8eb8-0d2f4dbd25a4",
      "expiresAt": 1731402972,
      "clientId": "test-app",
      "clientName": "Test App"
    }
  ]
}
```

If the credential referenced by the device assertion does not own an outstanding challenge, the array is empty even if other devices for the same user are awaiting approval.

If the authenticator is configured with `userVerification`, each entry also includes a `userVerification` object:

- `{"type":"number-match","numbers":["5","34","56"]}` – show the three options and let the user tap the number shown in the browser (values are strings in the range `0`–`99` without leading zeros).
- `{"type":"pin","pinLength":<n>}` – ask the user to enter the PIN shown in the browser (`pinLength` matches `userVerificationPinLength`). The PIN may start with `0`, so send it as a string and preserve leading zeros in `userVerification`.

`expiresAt` is expressed in Unix seconds (the same format used by JWT `exp` claims) so the device can reuse its existing JWT helpers for deadline calculations.

## Approve or Deny a Challenge

```
POST /realms/<realm>/push-mfa/login/challenges/{cid}/respond
Authorization: DPoP <access-token>
DPoP: <proof JWT>
Content-Type: application/json

{
  "token": "<device-signed login JWT>"
}
```

Keycloak verifies the DPoP proof to authenticate the device, then validates the login token (stored in the request body) with the saved JWK. The login token must carry `cid`, `credId`, `deviceId`, and `action`. `"action": "approve"` marks the challenge as approved; `"action": "deny"` marks it as denied. Any other value is rejected. When `userVerification` is enabled, `"action": "approve"` also requires `userVerification` (selected number / entered PIN); `"deny"` never does.

If two response requests race for the same challenge, the loser may receive `409 Conflict`. Clients should treat that as a same-challenge concurrency signal and re-read current state rather than assuming the operation failed globally.

**Success Response:**
```json
{ "status": "approved" }
```

**Error Responses (when `userVerification` is enabled):**

Missing (`400`):
```json
{ "error": "Missing user verification" }
```

Mismatch (`403`):
```json
{ "error": "User verification mismatch" }
```

Concurrent same-challenge resolution (`409`):
```json
{ "error": "Challenge is currently being resolved" }
```

## Lock Out User

```
POST /realms/<realm>/push-mfa/login/lockout
Authorization: DPoP <access-token>
DPoP: <proof JWT>
```

No request body. The DPoP proof authenticates the device and identifies the user. Keycloak disables the user account (`enabled=false`), preventing any further logins until an administrator re-enables the account.

This endpoint acts as a panic button: if the user suspects their account is compromised, the mobile app can immediately lock the account from the device.

**Response:**
```json
{
  "status": "locked_out"
}
```

## Update the Push Provider

```
PUT /realms/<realm>/push-mfa/device/push-provider
Authorization: DPoP <access-token>
DPoP: <proof JWT>
Content-Type: application/json

{
  "pushProviderId": "new-provider-token",
  "pushProviderType": "none"
}
```

Keycloak authenticates the request with the current user key and replaces the stored push provider identifier and/or type tied to that credential. The response body is `{ "status": "updated" }` (or `"unchanged"` if the values were already in sync). Use this endpoint whenever your downstream push provider rotates registration tokens (e.g., new FCM registration token, APNs device token refresh, proprietary push subscription id, etc.), or when you want to switch to a different `PushNotificationSender` implementation. Set `pushProviderType` to `none` when the app has push notifications disabled and you want Keycloak to skip delivery without producing missing-provider errors; later, call the same endpoint again with the restored provider metadata. Omitting `pushProviderType` keeps the existing type.

When `pushProviderType` is `none`, the server still stores `pushProviderId` as opaque device metadata even though the no-op sender ignores it. Use any stable placeholder your app understands, such as `disabled`.

> Demo helper: `scripts/update-push-provider.sh <credential-id> <provider-id> [provider-type]`

## Rotate the User Key

```
PUT /realms/<realm>/push-mfa/device/rotate-key
Authorization: DPoP <access-token>
DPoP: <proof JWT>
Content-Type: application/json

{
  "publicKeyJwk": {
    "kty": "RSA",
    "n": "....",
    "e": "AQAB",
    "alg": "RS256",
    "use": "sig",
    "kid": "user-key-rotated"
  }
}
```

The DPoP proof must be signed with the *existing* user key. After validation, Keycloak swaps the stored JWK (and updates the credential timestamp). The response is `{ "status": "rotated" }`. Future API calls must be signed with the newly-installed key.

> Demo helper: `scripts/rotate-user-key.sh <credential-id>`

## Demo CLI Scripts

The repository includes thin shell wrappers that simulate a device:

- `scripts/enroll.sh <enrollment-token|request-uri|deep-link>` resolves the enrollment input to the enrollment JWT, decodes it, generates a key pair (RSA or EC), and completes enrollment.
- `scripts/confirm-login.sh <confirm-token>` decodes the Firebase-style payload, lists pending challenges (for demo visibility), and approves/denies the challenge (set `LOGIN_USER_VERIFICATION` or use the prompt when `userVerification` is enabled).
- `scripts/update-push-provider.sh <credential-id> <provider-id> [provider-type]` updates the stored push provider metadata (defaults to the `log` provider used in this demo, but also accepts `none` to disable delivery intentionally).
- `scripts/rotate-user-key.sh <credential-id>` rotates the user key material and immediately persists the new JWK.

All scripts source `scripts/common.sh`, which centralizes base64 helpers, compact-JWS signing, DPoP proof creation, and token acquisition. The helper expects `scripts/sign_jws.py` to exist (or `COMMON_SIGN_JWS` to point to a compatible signer), so replacing the demo logic with a real implementation only requires swapping in a different signer.
