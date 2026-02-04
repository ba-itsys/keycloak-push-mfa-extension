# Keycloak Push MFA Extension

[![Maven Central](https://img.shields.io/maven-central/v/de.arbeitsagentur.opdt/keycloak-push-mfa-extension)](https://central.sonatype.com/artifact/de.arbeitsagentur.opdt/keycloak-push-mfa-extension)

A Keycloak extension that adds push-based multi-factor authentication, similar to passkey primitives.

## Quick Start

### Using Maven (recommended)

Add the dependency to your project:

```xml
<dependency>
    <groupId>de.arbeitsagentur.opdt</groupId>
    <artifactId>keycloak-push-mfa-extension</artifactId>
    <!-- Check the badge above or Maven Central for the latest version -->
    <version>1.5.0</version>
</dependency>
```

Copy the JAR to Keycloak's `providers/` directory and restart Keycloak.

### Building from Source

```bash
# Build the provider
mvn -DskipTests package

# Run Keycloak with the demo realm
docker compose up
```

- **Keycloak Admin Console:** http://localhost:8080 (login: `admin` / `admin`)
- **Demo Realm:** `demo` with test user `test` / `test`
- **Demo Configuration:** See `config/demo-realm.json` for a working example

## Introduction

This project extends Keycloak with a push-style second factor that mimics passkey primitives. After initial enrollment, the mobile app never receives the real user identifier from Keycloak; instead, it works with a credential id that only the app can map back to the real user. Everything is implemented with standard Keycloak SPIs plus a small JAX-RS resource exposed under `/realms/<realm>/push-mfa`.

## High Level Flow

```mermaid
sequenceDiagram
    autonumber
    participant Browser as User / Browser
    participant Keycloak as Keycloak Server
    participant Provider as Push Provider (FCM/APNs)
    participant Mobile as Mobile App

    Note over Browser, Mobile: **Phase 1: Enrollment (Register Push MFA Device)**

    Browser->>Keycloak: Login & Trigger Enrollment
    Keycloak-->>Browser: Render QR Code & Start SSE Listener

    par Parallel Actions
        Browser->>Keycloak: SSE Connection (Watch Status)
        Browser->>Mobile: Scan QR Code
    end

    Note over Mobile: Verify Token & Generate User Key Pair

    Mobile->>Keycloak: POST /enroll/complete
    Note right of Mobile: Payload: Device JWT + Public JWK<br/>Signed with new Device Private Key

    Keycloak->>Keycloak: Verify Signature & Store Device Credential
    Keycloak-->>Browser: SSE Event: { status: "APPROVED" }
    Browser->>Keycloak: Auto-Submit Form (Enrollment Complete)

    Note over Browser, Mobile: **Phase 2: Login (Push MFA Confirmation)**

    Browser->>Keycloak: Login (Username/Password)
    Keycloak->>Keycloak: Generate Challenge & ConfirmToken

    par Parallel Actions
        Keycloak-->>Browser: Render "Waiting for approval..." Page
        Browser->>Keycloak: SSE Connection (Watch Challenge)
        Keycloak->>Provider: Send Push Notification
        Note right of Keycloak: Payload: ConfirmToken<br/>(Credential ID, ChallengeID)
    end

    Provider->>Mobile: Deliver Push Notification

    Mobile->>Mobile: Decrypt Token & Resolve User ID
    Mobile-->>Browser: (User Prompt: Approve?)
    Browser-->>Mobile: User Taps "Approve"

    Mobile->>Keycloak: POST /login/challenges/{cid}/respond
    Note right of Mobile: Payload: LoginToken (Action: Approve)<br/>Auth: DPoP Header + Access Token<br/>Signed with Device Private Key

    Keycloak->>Keycloak: Verify DPoP, Signature & Challenge ID
    Keycloak-->>Browser: SSE Event: { status: "APPROVED" }
    Browser->>Keycloak: Auto-Submit Form (Login Success)
```

## Documentation

| Document | Description |
|----------|-------------|
| [Setup Guide](docs/setup.md) | Step-by-step configuration instructions and Keycloak concepts |
| [Flow Details](docs/flow-details.md) | Technical details of enrollment, login, SSE, and DPoP authentication |
| [API Reference](docs/api-reference.md) | REST endpoints for mobile apps |
| [Configuration](docs/configuration.md) | All configuration options reference |
| [App Implementation](docs/app-implementation.md) | Guide for mobile app developers |
| [SPI Reference](docs/spi-reference.md) | Push notification, event, and rate limiting SPIs |
| [UI Customization](docs/ui-customization.md) | Theme and template customization |
| [Security](docs/security.md) | Security model and mobile app obligations |
| [Mobile Mock](docs/mobile-mock.md) | Testing without a real mobile app |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and solutions |
