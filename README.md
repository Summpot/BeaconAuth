# BeaconAuth

BeaconAuth is an authentication system for Minecraft communities, with a web UI, an API (server + Worker), and a companion mod for in-game login.

[![Build](https://github.com/Summpot/BeaconAuth/actions/workflows/build.yml/badge.svg)](https://github.com/Summpot/BeaconAuth/actions/workflows/build.yml)
[![Release](https://github.com/Summpot/BeaconAuth/actions/workflows/release.yml/badge.svg)](https://github.com/Summpot/BeaconAuth/actions/workflows/release.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Summpot/BeaconAuth)

## Docs

Documentation is maintained under `content/docs` (Fumadocs).

- [Getting started](content/docs/getting-started.mdx)
- [Configuration](content/docs/configuration.mdx)
- [Development](content/docs/development.mdx)
- [Server deployment](content/docs/server-deployment.mdx)
- [Cloudflare deployment](content/docs/cloudflare-deployment.mdx)
- [Mod installation](content/docs/mod-installation.mdx)
- [Troubleshooting](content/docs/troubleshooting.mdx)

## Quick start (Docker)

The published container image runs the server binary (`beacon`) and listens on `:8080`.

```bash
docker run --rm -p 8080:8080 \
  -e BIND_ADDRESS=0.0.0.0:8080 \
  -e BASE_URL=http://localhost:8080 \
  -e DATABASE_URL=sqlite:///app/data/beacon_auth.db?mode=rwc \
  -v beaconauth-data:/app/data \
  ghcr.io/summpot/beaconauth:latest
```

After it starts:

- UI: `http://localhost:8080/`
- JWKS: `http://localhost:8080/.well-known/jwks.json`

## Local development

The web app (UI + docs) is a Vite project:

```bash
pnpm install
pnpm dev
```

For backend / Worker development and deployment options, see the docs linked above.

## Support

- Issues: <https://github.com/Summpot/BeaconAuth/issues>
- Discussions: <https://github.com/Summpot/BeaconAuth/discussions>
