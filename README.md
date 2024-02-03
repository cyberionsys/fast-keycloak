# FastAPI Keycloak Integration

[![Test-Suite](https://github.com/cyberionsys/fast-keycloak/actions/workflows/tests.yaml/badge.svg)](https://github.com/cyberionsys/fast-keycloak/actions/workflows/tests.yaml)
[![codecov](https://codecov.io/gh/cyberionsys/fast-keycloak/branch/master/graph/badge.svg?token=PX6NJBDUJ9)](https://codecov.io/gh/cyberionsys/fast-keycloak)
![Py3.12](https://img.shields.io/badge/-Python%203.12-brightgreen)
[![CodeQL](https://github.com/cyberionsys/fast-keycloak/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyberionsys/fast-keycloak/actions/workflows/codeql.yml)

## Introduction

Welcome to `fastapi-keycloak`. This projects goal is to ease the integration of Keycloak (OpenID Connect) with Python, especially FastAPI. FastAPI is not necessary but is
encouraged due to specific features. Currently, this package supports only the `password` and the `authorization_code`. However, the `get_current_user()` method accepts any JWT
that was signed using Keycloak´s private key.

## TLDR

FastAPI Keycloak enables you to do the following things without writing a single line of additional code:

- Verify identities and roles of users with Keycloak
- Get a list of available identity providers
- Create/read/delete users
- Create/read/delete roles
- Create/read/delete/assign groups (recursive). Thanks to @fabiothz
- Assign/remove roles from users
- Implement the `password` or the `authorization_code` flow (login/callback/logout)

## Testing

Tests are stored and executed in `./tests`. To test the package, it is necessary to use the `start_infra.sh` script upfront, to set up Keycloak and Postgres. We do this to avoid
artificial testing conditions that occur by mocking all the keycloak requests. Run them with `poetry run pytest`