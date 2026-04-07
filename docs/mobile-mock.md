# Mobile Mock for Push MFA

The `mock/mobile` folder contains a mock implementation simulating the behavior of a mobile application for testing the Keycloak Push MFA Extension. This mock is particularly useful for development and integration testing without requiring a real mobile device or app.

## Overview

This mock mimics the enrollment and login confirmation flows described in the project's documentation, allowing developers to verify the server-side logic (e.g., Keycloak SPIs and JAX-RS endpoints) in isolation.

The mock is built using TypeScript and Node.js, leveraging packages like Express for creating a simple HTTP server that handles push notifications, token processing, and user interactions. It does not represent a production-ready mobile app but serves as a testing utility.

### Purpose

- **Testing Login & Enrollment Flow**: Simulates scanning a QR code, generating key pairs, and completing enrollment and login via API calls.

This folder is not part of the core Keycloak provider but is included for developer convenience. It can be run locally alongside the Keycloak Docker setup.

## Setup and Usage

A working mock is available in the artifact in the mock folder.

### Prerequisites

- Node.js (compatible with @types/node 22.7.5)
- npm for package management
- Install dependencies: Run `npm install` in the `mock/mobile` folder

### Running the Mock

1. Build the app:
```bash
npm run build
```

2. Start the server:
```bash
npm run start
```

The mock server listens on a port (e.g., 3001) and exposes endpoints like:
- `/enroll`: POST endpoint to mimic QR code scanning and enrollment completion
- `/confirm-login`: POST endpoint to process a Keycloak `confirmToken` and respond to the login challenge (`action=approve|deny`, plus optional `userVerification` for number-match / PIN)

## Example Integration with Keycloak Flow

### Simulating Enrollment

The mock can "scan" a QR code by receiving the `enrollmentToken` directly, or by first resolving a `request_uri` to that JWT when by-reference enrollment is enabled. It then generates a device key pair and sends a signed payload to Keycloak's `/enroll/complete` endpoint.

### Simulating Login Approval

1. Receives a mock push notification with `ConfirmToken`
2. Prompts for approval (via console or UI)
3. Sends a signed `LoginToken` to Keycloak's `/login/challenges/{cid}/respond`

For full flow details, refer to the [Flow Details](flow-details.md) documentation.

## Key Concepts in the Mock

- **Token Handling**: Uses jose for JWT signing/verification, ensuring compatibility with Keycloak's realm keys
- **DPoP (Demonstration of Proof-of-Possession)**: Mocked in headers for secure API calls
- **Push Simulation**: Instead of real FCM/APNs, the mock can be triggered directly via API for testing
- **Security Notes**: This is a mock; do not use real keys or expose it in production. Placeholders are used for any sensitive info (e.g., `<MOCK_DEVICE_ID>` instead of real UUIDs)
