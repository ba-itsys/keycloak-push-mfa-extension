# Firebase Cloud Messaging (FCM) Provider

This provider sends notifications to the FCM API if its ID, `fcm`, was used as the `providerId` during Push MFA enrollment.

## Prerequisites

To send requests to FCM API, a google service account is needed. The login credentials and certificate for this account must be provided in a JSON file, the FCM provider checks the `GOOGLE_APPLICATION_CREDENTIALS` environment variable for the path to this file. 

Additional to the google credentials the correct url to your project in FCM must be provided (https://fcm.googleapis.com/v1/projects/your-project-id/messages:send). Provide the url at `googleFcmUrl` (spi-push-notification-sender--fcm--google-fcm-url).

See the FCM documentation for further details on FCM [here](https://firebase.google.com/docs/cloud-messaging)

## Proxy

You can configure a proxy for FCM requests with any of the following environment variables (ranked as written): https_proxy, HTTPS_PROXY, http_proxy, HTTP_PROXY