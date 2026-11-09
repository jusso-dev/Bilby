# Security policy

## Reporting a problem

If you find a security problem in Bilby, please tell us privately. Use the **Report a vulnerability** button on the repository's [Security tab](https://github.com/jusso-dev/Bilby/security). Please don't open a public issue for it.

Tell us what you found, how to reproduce it and which version of Bilby you used. We'll reply as soon as we can and keep you updated while we work on a fix.

## What's in scope

- The Bilby desktop app and everything in this repository.
- Its build and release pipeline: GitHub Actions workflows, dependencies and release artifacts.

## What Bilby doesn't have

Bilby has no servers, accounts or telemetry. It doesn't send anything anywhere unless you switch on online checks, and then it only sends file fingerprints (SHA-256 hashes) to the services you choose. See [ADR 0004](docs/adr/0004-no-telemetry-opt-in-online-checks.md).

## Supported versions

Bilby is early and has no releases yet. Once it does, fixes go into the latest release.
