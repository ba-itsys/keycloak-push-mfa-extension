# Changelog

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
