# BeaconAuth

**BeaconAuth** is a modern, secure authentication system for Minecraft servers, featuring a web-based login interface with OAuth support and a companion mod for seamless in-game authentication.

[![Build](https://github.com/Summpot/beacon_auth/actions/workflows/build.yml/badge.svg)](https://github.com/Summpot/beacon_auth/actions/workflows/build.yml)
[![Release](https://github.com/Summpot/beacon_auth/actions/workflows/release.yml/badge.svg)](https://github.com/Summpot/beacon_auth/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Documentation

Documentation is maintained in `content/docs` and rendered with **Fumadocs**.

- [Docs home](content/docs/index.mdx)
- [Getting started](content/docs/getting-started.mdx)
- [Architecture](content/docs/architecture.mdx)
- [Configuration](content/docs/configuration.mdx)
- [Server deployment](content/docs/server-deployment.mdx)
- [Cloudflare deployment](content/docs/cloudflare-deployment.mdx)
- [Mod installation](content/docs/mod-installation.mdx)
- [Development guide](content/docs/development.mdx)
- [API reference](content/docs/api.mdx)
- [Troubleshooting](content/docs/troubleshooting.mdx)
- [Contributing](content/docs/contributing.mdx)

## Features

### Authentication Server
- 🔐 **ES256 JWT Authentication** - Industry-standard elliptic curve cryptography
- 🌐 **Modern Web Interface** - React-based login and registration pages
- 🍪 **Session Management** - Secure HttpOnly cookies with refresh token rotation
- 🔑 **OAuth Integration** - Support for GitHub, Google, and Microsoft authentication
- 🔒 **WebAuthn/Passkey Support** - Passwordless authentication with biometrics
- 🗄️ **SQLite Database** - Simple, file-based user storage
- 🐳 **Docker Ready** - Multi-architecture container images (amd64/arm64)
- ⚡ **High Performance** - Built with Rust and Actix-web

### Minecraft Mod
- 🎮 **Automatic Login Flow** - Seamless in-game authentication
- 🔒 **PKCE Security** - Proof Key for Code Exchange protection
- 🌍 **Multi-Loader Support** - Works with both Fabric and Forge
- 🌐 **Internationalization** - English and Chinese translations
- ⚙️ **Configurable** - Server-side TOML configuration
- 🔗 **JWT Validation** - Secure verification using JWKS

## Table of Contents

- [Quick Start](#quick-start)
  - [Using Docker (Recommended)](#using-docker-recommended)
  - [Using Pre-built Binaries](#using-pre-built-binaries)
  - [Building from Source](#building-from-source)
- [Cloudflare Deployment (Workers + Pages)](#cloudflare-deployment-workers--pages)
  - [One-time Cloudflare setup](#one-time-cloudflare-setup)
  - [GitHub Actions deployment](#github-actions-deployment)
  - [Routing (same-origin API)](#routing-same-origin-api)
- [Auth Server Deployment](#auth-server-deployment)
  - [Configuration](#configuration)
  - [Database Setup](#database-setup)
  - [OAuth Setup](#oauth-setup)
  - [Production Deployment](#production-deployment)

  ## License

  This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

  ## Support

  - **Issues**: [GitHub Issues](https://github.com/Summpot/beacon_auth/issues)
  - **Discussions**: [GitHub Discussions](https://github.com/Summpot/beacon_auth/discussions)
docker run -d --name beaconauth \
