# BeaconAuth

BeaconAuth is an authentication platform for Minecraft communities. It combines a Rust auth
server, a React web UI, and a multi-loader Minecraft mod so servers can require secure web,
OAuth, or passkey login before players enter the game.

[![Build](https://github.com/Summpot/BeaconAuth/actions/workflows/build.yml/badge.svg)](https://github.com/Summpot/BeaconAuth/actions/workflows/build.yml)
[![Release](https://github.com/Summpot/BeaconAuth/actions/workflows/release.yml/badge.svg)](https://github.com/Summpot/BeaconAuth/actions/workflows/release.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Summpot/BeaconAuth)

## What It Provides

- ES256 JWT authentication with JWKS distribution for game-server verification.
- Web UI for registration, login, profile management, OAuth completion, and passkeys.
- OAuth provider support for GitHub, Google, and Microsoft.
- Minecraft login flow with PKCE and signed token verification.
- Server deployment as a native binary, Docker image, or Cloudflare Worker.
- Localized web and in-game text across the supported languages in this repository.

## Repository Layout

- `crates/`: Rust server, shared auth logic, database entities, migrations, and serverless runtimes.
- `src/`: React web UI and app routes.
- `content/docs/`: Fumadocs documentation.
- `messages/`: Paraglide localization files for the web UI.
- `modSrc/`: Architectury-based Minecraft mod for Fabric, Forge, and NeoForge.

## Quick Start

The published container image runs the `beacon` server and listens on port `8080`.

```bash
docker run --rm -p 8080:8080 \
  -e BIND_ADDRESS=0.0.0.0:8080 \
  -e BASE_URL=http://localhost:8080 \
  -e DATABASE_URL=sqlite:///app/data/beacon_auth.db?mode=rwc \
  -v beaconauth-data:/app/data \
  ghcr.io/summpot/beaconauth:latest
```

After startup:

- Web UI: `http://localhost:8080/`
- JWKS endpoint: `http://localhost:8080/.well-known/jwks.json`

## Minecraft Mod

BeaconAuth ships a companion mod that connects Minecraft clients and servers to the auth
server. The mod is intended to be installed on both the server and clients that need to
complete the in-game login flow.

Supported build targets:

| Minecraft | Loader |
| --- | --- |
| 1.20.1 | Fabric, Forge |
| 1.21.1 | Fabric, NeoForge |
| 1.21.8 | Fabric, NeoForge |

Release jars are produced by the `modSrc` Gradle build and by the `Mod` GitHub Actions
workflow. See the [mod installation guide](content/docs/mod-installation.mdx) for file
selection, installation, and server configuration.

## Documentation

Documentation is maintained in Fumadocs under `content/docs`.

- [Getting started](content/docs/getting-started.mdx)
- [Configuration](content/docs/configuration.mdx)
- [Server deployment](content/docs/server-deployment.mdx)
- [Cloudflare deployment](content/docs/cloudflare-deployment.mdx)
- [Mod installation](content/docs/mod-installation.mdx)
- [Network and privacy](content/docs/network-privacy.mdx)
- [Troubleshooting](content/docs/troubleshooting.mdx)
- [Architecture](content/docs/architecture.mdx)
- [Development](content/docs/development.mdx)
- [API reference](content/docs/api.mdx)
- [Contributing](content/docs/contributing.mdx)

## Local Development

Requirements:

- Java 21 for the Minecraft mod build.
- Rust stable for the server crates.
- Node.js and pnpm for the web UI and docs.

The web app and docs use Vite:

```bash
pnpm install
pnpm dev
```

Rust server validation:

```bash
cargo check --all-targets
cargo build -p beacon-worker --target wasm32-unknown-unknown
```

Minecraft mod validation:

```bash
cd modSrc
./gradlew build
```

## Support

- Issues: <https://github.com/Summpot/BeaconAuth/issues>
- Discussions: <https://github.com/Summpot/BeaconAuth/discussions>

## License

MIT. See [LICENSE](LICENSE).
