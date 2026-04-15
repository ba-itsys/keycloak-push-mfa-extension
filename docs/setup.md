# Setup Guide

This guide walks you through setting up Push MFA in your Keycloak instance. The demo realm (`config/demo-realm.json`) provides a working example of all these configurations.

## Keycloak Concepts (Quick Primer)

If you're new to Keycloak, here's a quick overview of the concepts used in this extension:

| Concept | What it is | How it's used here |
|---------|-----------|-------------------|
| **Realm** | An isolated security domain in Keycloak. Each realm has its own users, clients, and settings. | The demo uses a realm called `demo`. |
| **Authentication Flow** | A sequence of steps a user must complete to log in. Flows are made up of "executions" (authenticators). | We create `browser-push-flow` with username/password + push MFA. |
| **Authenticator** | A single step in an authentication flow (e.g., password check, OTP verification). | `push-mfa-authenticator` sends push notifications and waits for approval. |
| **Required Action** | A one-time task a user must complete (e.g., reset password, configure OTP). | `push-mfa-register` handles device enrollment via QR code. |
| **Client** | An application that uses Keycloak for authentication. | `test-app` (web app) and `push-device-client` (mobile device API). |

## Step 1: Deploy the Extension

1. Build the provider:
   ```bash
   mvn -DskipTests package
   ```

2. Copy the JAR to Keycloak's `providers/` directory, or use Docker Compose (which does this automatically):
   ```bash
   docker compose up
   ```

## Step 2: Enable the Required Action (for Enrollment)

The **Required Action** allows users to enroll their mobile device by scanning a QR code.

**Via Admin Console:**
1. Go to **Authentication → Required Actions**
2. Find `Register Push MFA device` in the list
3. Toggle **Enabled** to ON
4. (Optional) Toggle **Default Action** to ON if you want all users to enroll automatically

**What the demo realm does** (see `config/demo-realm.json:72-81`):
```json
"requiredActions": [
  {
    "alias": "push-mfa-register",
    "name": "Register Push MFA device",
    "providerId": "push-mfa-register",
    "enabled": true,
    "defaultAction": false,  // Set to true to force enrollment for all users
    "priority": 100
  }
]
```

**To trigger enrollment for a specific user:**
1. Go to **Users → [select user] → Required Actions**
2. Add `Register Push MFA device` to the user's pending actions

## Step 3: Create an Authentication Flow (for Login)

The **Authenticator** handles the push notification during login. You need to add it to an authentication flow.

**Via Admin Console:**
1. Go to **Authentication → Flows**
2. Click **Create flow** or duplicate the built-in `browser` flow
3. Add these executions in order:
   - `Cookie` (ALTERNATIVE) — allows session cookies to skip login
   - `Identity Provider Redirector` (ALTERNATIVE) — for social/federated login
   - A **sub-flow** (ALTERNATIVE) containing:
     - `Username Password Form` (REQUIRED)
     - `Push MFA Authenticator` (REQUIRED)

**What the demo realm does** (see `config/demo-realm.json:82-131`):

The demo creates two flows:

1. **`browser-push-flow`** (top-level flow):
   ```
   ├── Cookie                          [ALTERNATIVE]
   ├── Identity Provider Redirector    [ALTERNATIVE]
   └── browser-push-forms (sub-flow)   [ALTERNATIVE]
   ```

2. **`browser-push-forms`** (sub-flow):
   ```
   ├── Username Password Form          [REQUIRED]
   └── Push MFA Authenticator          [REQUIRED]
   ```

The sub-flow pattern ensures that push MFA only triggers after successful password authentication.

## Step 4: Bind the Flow to the Realm

**Via Admin Console:**
1. Go to **Authentication → Flows**
2. Click the **⋯** menu next to your flow
3. Select **Bind flow** → **Browser flow**

Or go to **Realm Settings → Authentication** and set **Browser flow** to your custom flow.

**What the demo realm does** (see `config/demo-realm.json:9`):
```json
"browserFlow": "browser-push-flow"
```

## Step 5: Create the Device Client

The mobile app needs a confidential client to obtain DPoP-bound access tokens.

**Via Admin Console:**
1. Go to **Clients → Create client**
2. Set:
   - **Client ID**: `push-device-client`
   - **Client authentication**: ON
   - **Service accounts roles**: ON
   - **Standard flow**: OFF
   - **Direct access grants**: OFF
3. In the **Credentials** tab, note the client secret
4. In the **Advanced** tab, enable **DPoP bound access tokens**

**What the demo realm does** (see `config/demo-realm.json:24-36`):
```json
{
  "clientId": "push-device-client",
  "publicClient": false,
  "serviceAccountsEnabled": true,
  "secret": "device-client-secret",
  "attributes": {
    "dpopBoundAccessTokens": "true"
  }
}
```

## Step 6: Configure the Authenticator (Optional)

To customize the authenticator behavior:

**Via Admin Console:**
1. Go to **Authentication → Flows**
2. Open your flow and find `Push MFA Authenticator`
3. Click the **⚙️ gear icon** to configure:
   - **Login challenge TTL** — how long the push notification is valid
   - **Max pending challenges** — concurrent logins per user
   - **User verification** — `none`, `number-match`, or `pin`

**Via CLI:**
```bash
# Get the execution ID first
EXEC_ID=$(kcadm.sh get authentication/flows/browser-push-forms/executions -r demo \
  --fields id,displayName | jq -r '.[] | select(.displayName=="Push MFA Authenticator") | .id')

# Update configuration
kcadm.sh create authentication/executions/$EXEC_ID/config -r demo \
  -s alias=push-mfa \
  -s config.loginChallengeTtlSeconds=180 \
  -s config.userVerification=number-match
```

## Step 7: Configure the Required Action (Optional)

To customize enrollment behavior:

**Via Admin Console:**
1. Go to **Authentication → Required Actions**
2. Click **Configure** next to `Register Push MFA device`
3. Set:
   - **Enrollment challenge TTL** — how long the QR code is valid
   - **App universal link** — deep link scheme for your mobile app

**Via CLI:**
```bash
kcadm.sh update authentication/required-actions/push-mfa-register -r demo \
  -s "config.enrollmentChallengeTtlSeconds=300" \
  -s "config.enrollmentAppUniversalLink=myapp://enroll"
```
