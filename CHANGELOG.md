# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [0.1.3] - 2025-03-05

### Fixed
- The version bump script now includes `uv.lock` in the release commit.

---

## [0.1.2] - 2025-03-05

### Changed
- The version bump script now refreshes `uv.lock` with `uv lock`.

---

## [0.1.1] - 2025-03-05

### Added
- Initial release.
- Download and decryption of location reports from Apple's Find My network.
- Conversion of private Find My keys to public keys.
- Publishing of decrypted locations to an MQTT broker in the OwnTracks JSON format.
- Support for public and self-hosted Anisette servers.
- Interactive Apple ID authentication, including SMS and trusted-device two-factor authentication.
- Docker Compose setup with the OwnHaystack, Mosquitto, Anisette and OwnTracks Recorder services.
- Configuration through environment variables.
- Version bump script.
- GitHub Actions workflow for publishing Docker images.

### Changed
- Renamed the project from Macless Haystack OwnTracks to OwnHaystack.

### Fixed
- Improved Anisette authentication compatibility.
- Print tracebacks when unexpected errors occur.
