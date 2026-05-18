# Push MFA Simulator

The Keycloak Push MFA Simulator is a small application that
1. simulates a mobile app for push mfa enrollment an push mfa confirm
2. simulates firebase cloud messaging backend to receive the push notification requests and provide it on UI via server sent events

A detailed documentation can be found [here](https://github.com/ba-itsys/keycloak-push-mfa-extension-simulator)

## Run

Use docker compose with the provided docker-compose.yaml to run an instance of the Push MFA Simulator on `http://localhost:5000/`.