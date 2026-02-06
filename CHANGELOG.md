# Changelog

## [1.5.3](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.5.2...v1.5.3) (2026-02-06)


### Bug Fixes

* fire UPDATE_CREDENTIAL on successful enrollment, introduce event details constants ([d9f4036](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/d9f403678bded28f04390c0eaf9dbcbd5e4da8b9))

## [1.5.2](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.5.1...v1.5.2) (2026-02-05)


### Bug Fixes

* add security tests, fix docs, refactor for extensibility ([045a883](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/045a88328aa576a9d3ba3116441b8510ea3493ca))
* update default challenge ttl, fix readme inconsistencies, refactor class structure ([52d1072](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/52d107275b6cbf2e3ad5f5259c9fc04f87c13b33))

## [1.5.1](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.5.0...v1.5.1) (2026-02-04)


### Bug Fixes

* **waitchallenge:** use keycloak spi mechanism to select storage provider ([f040cd8](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/f040cd88a0bf7b4f9265bbe461164fa4a22e6880))


### Documentation

* **structure:** split README into multiple, more concise docs ([99745cd](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/99745cd2c4e73b95be224d7fb518b7b8106a6e01))

## [1.5.0](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.4.0...v1.5.0) (2026-02-04)


### Features

* **events:** add event listener spi + keycloak event bridge ([b789da8](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/b789da859115277c3335a30f2a514e993d9cdfa5))
* **security:** add optional wait challenge ([c40c15d](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/c40c15d07a582bde925617ec54e5f569fbe7a1e0))

## [1.4.0](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.3.2...v1.4.0) (2026-01-16)


### Bug Fixes

* adds documentation ([191c969](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/191c9696cbdec2b858f5aa7ca02796d07c0b2d2f))

## [1.3.2](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.3.1...v1.3.2) (2026-01-13)


### Documentation

* add openApi spec for PushMfaResource ([#60](https://github.com/ba-itsys/keycloak-push-mfa-extension/issues/60)) ([a4403bc](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/a4403bc6c71917c70d4dc24dd8bd430ce7c69e7e))

## [1.3.1](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.3.0...v1.3.1) (2026-01-08)


### Bug Fixes

* registering push-mfa credential on account page did not work ([#57](https://github.com/ba-itsys/keycloak-push-mfa-extension/issues/57)) ([59a036b](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/59a036bce6e0e610c84dc11ab1cd2b3b1f8a069f))

## [1.3.0](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.2.0...v1.3.0) (2025-12-19)


### Features

* optionally add correct userVerification answer to same device app-link ([870ddf5](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/870ddf566d159dca2db51cf275b0a2c9e6030997))

## [1.2.0](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.1.3...v1.2.0) (2025-12-19)


### Features

* add user verification modes (none, pin, match-numbers) ([5405625](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/5405625973974d240edd29e28c598b653fbc8dff))


### Bug Fixes

* fix flaky test ([00d6ca8](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/00d6ca8a6b83324017eea6652d7fcbd3a8f4cb3a))

## [1.1.3](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.1.2...v1.1.3) (2025-12-15)


### Bug Fixes

* **security:** add input constraints/validations and SSE hardening ([481682d](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/481682d16faf615243bc035798294c2d9c036bd2))

## [1.1.2](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.1.1...v1.1.2) (2025-12-15)


### Bug Fixes

* add mock integration tests ([d0d1554](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/d0d1554fc3e59be5306ce16f699d18c366cb7232))

## [1.1.1](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.1.0...v1.1.1) (2025-12-11)


### Bug Fixes

* cleanup jwk/alg and fix concurrent challenges / refresh bug ([0522ed1](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/0522ed1df8e31c18b976916005d02fa4c9c0f4c8))

## [1.1.0](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.0.2...v1.1.0) (2025-12-10)


### Features

* add username to pending-response, remove client-id/name from push token ([ccb9ce2](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/ccb9ce2f0f6f6e71758cbe1e30028245aa91ca4e))


### Bug Fixes

* **docs:** README & Deeplink in übereinstimmung bringen ([#35](https://github.com/ba-itsys/keycloak-push-mfa-extension/issues/35)) ([7ad8ae3](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/7ad8ae33ad21162557fc299d9c6eabbb908d5e85))
* remove dedicated algorithm field from credential and rotation endpoint (is part of jwk itself) ([dd19c1b](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/dd19c1bfcdedbcbb7951f71c35fd3473a9b34639))

## [1.0.2](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.0.1...v1.0.2) (2025-12-09)


### Bug Fixes

* move beans.xml from META-INF.services to META-INF ([7e007e0](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/7e007e0264dabb30fbff316befcaf0b225776688))
* move beans.xml from META-INF.services to META-INF ([38a7ab4](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/38a7ab468607b7f11f5ab802f4345ff62f914e43))

## [1.0.1](https://github.com/ba-itsys/keycloak-push-mfa-extension/compare/v1.0.0...v1.0.1) (2025-12-09)


### Bug Fixes

* adds beans.xml for realm-provider propagation ([a72feca](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/a72fecaee592e4994e225afb774018409f122dcd))
* adds beans.xml for realm-provider propagation ([0a24d34](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/0a24d34afbcfbd6af8c8981cb551a66affecbe6c))
* **ci:** update sortPom configuration to disable expanding empty elements ([890dd03](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/890dd03b2314c660f7de861c5d8c3f3db2abb823))


### Documentation

* add PR template and update contributing guidelines ([cbee3a8](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/cbee3a85cc75b4f8e798828f6af96e35011b14ed))
* add PR template and update contributing guidelines ([4234ede](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/4234ede4986d99bcde38eba6506db8255041448b))
* **contributing:** remove redundant section on signed-off commits ([c75ccb9](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/c75ccb952043b1a50df4332467ec04d8eeb60343))

## 1.0.0 (2025-12-05)


### Features

* **build:** add source and javadoc JAR generation in Maven build ([24f29b7](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/24f29b7a23bc3316a278eb0882588a398a1d1087))
* **ci, build:** add Maven Central publishing configuration and workflow ([0fe8f3c](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/0fe8f3cc9df192ad20cfef5d4a89b17dcb8b4178))
* **ci:** add GitHub Actions workflow for automated releases using release-please ([de89029](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/de890293d2d749d4aa23c706301fcd8583ca0072))
* **docs:** add mermaid sequence diagram for Push MFA process in README ([af196df](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/af196df4d1e10924fe9fe77de952a722bfa882cb))


### Bug Fixes

* **docs:** update command in README to remove redundant `--build` flag ([e363b07](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/e363b078e00f9185d510f8f5ea98930b25d8aa6e))
* **i18n:** correct spelling in Push MFA cancellation message ([555b9cd](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/555b9cdac84a9685d3bdcfc867793f033e3709c4))
* mvn deploy ([9504e67](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/9504e67e7ade664582cb1f976d72d05d70c97017))
* **templates:** update templates to use v5 patternfly variables ([087eb27](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/087eb27e92818a86c10223976ab17b47606937c0))
* use credId instead of sub as claim in login token ([e19bfaf](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/e19bfaf5cdd22bcff8d77ce8a43dbf018a91d4d2))
* use credId instead of sub as claim in login token ([cc7da1a](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/cc7da1a47a076a976aab30ab193706a8f89beb7a))


### Documentation

* **contributing:** add CONTRIBUTING.md guide for contributors ([a0ffc1c](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/a0ffc1c09cf840802f194e6bccb0e3662d1dc1a9))
* **readme:** add troubleshooting guide for integration test issues ([d3d6ead](https://github.com/ba-itsys/keycloak-push-mfa-extension/commit/d3d6ead78286fc4c9c4100d942ec307b4490c923))
