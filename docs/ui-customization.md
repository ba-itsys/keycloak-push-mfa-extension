# UI Customization

The provider ships with a lightweight theme fragment under `src/main/resources/theme-resources/`. When the extension is built, those assets are copied into the deployed theme so you can either customize them in-place or copy them into your own Keycloak theme module and override the templates via standard theme selection.

## Theme Resources

### Enrollment (Required Action)

**Template:** `templates/push-register.ftl`

Renders the QR code, enrollment token, and SSE watcher while the user finishes onboarding. The markup is fully self-contained: everything is driven by `data-push-*` attributes on the root element plus localized strings from `messages/messages_en.properties`.

To restyle the screen, replace the HTML/CSS and keep emitting the same attributes (or call `KeycloakPushMfa.initRegisterPage(...)` manually) so the QR code and SSE wiring continue to function.

### Login Waiting UI

**Template:** `templates/push-wait.ftl`

Powers the "waiting for approval" screen. It subscribes to the challenge SSE endpoint via the same data attributes and optionally shows the confirm token for demo purposes. The "Open App" button uses the same-device link token (optionally carrying `userVerification` when `sameDeviceIncludeUserVerification=true`).

Swap the layout or remove the token preview altogether; just ensure the `data-push-*` attributes remain if you still rely on `KeycloakPushMfa.initLoginPage(...)`.

### Rate Limit Waiting UI

**Template:** `templates/push-wait-required.ftl`

Displays a countdown when the user must wait before retrying (when [Wait Challenge Rate Limiting](spi-reference.md#wait-challenge-rate-limiting) is enabled). Shows remaining wait time and a disabled retry button that enables when the wait expires.

### Terminal Pages

**Templates:**
- `templates/push-denied.ftl` - Explains when a login was canceled or denied
- `templates/push-expired.ftl` - Explains when a login challenge expired

These files only display localized strings, so they are easy to rebrand or translate by editing the template and updating the corresponding entries in `messages/messages_<locale>.properties`.

## JavaScript Library

All shared browser behavior (SSE handling, QR rendering, clipboard helpers) lives in `resources/js/push-mfa.js`. The script exposes:

- `KeycloakPushMfa.initRegisterPage` - Initialize enrollment page
- `KeycloakPushMfa.initLoginPage` - Initialize login waiting page
- `KeycloakPushMfa.autoInit` - Auto-initialize based on page context

If you move to a different frontend stack you can reuse those helpers or replace them entirely with your own EventSource/QR logic.

## Customization Approach

Because every UI asset is a regular Keycloak theme resource, you customize them the same way as any other login theme:

1. Copy the template/JS/message files into your custom theme folder
2. Adjust them as needed
3. Point the realm to that theme via the admin console or `keycloak.conf`

## Localization

Message strings are stored in `messages/messages_<locale>.properties`. To add a new language or modify existing strings:

1. Copy `messages_en.properties` to `messages_<locale>.properties`
2. Translate the string values
3. Deploy with your theme

The templates reference these strings using Keycloak's standard message resolution mechanism.
