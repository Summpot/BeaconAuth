# Instructions for Summpot/BeaconAuth

## 1) Execution Principles

* Prefer completing tasks in a single integrated pass.
* If a task is truly large, create a concrete plan and still deliver a complete end-to-end implementation (do not land partial behavior).
* Integration over isolation: when adding or changing functionality, also update imports, wiring, and call sites in the same pass.
* Ask for user confirmation only when genuinely ambiguous (requirements, security tradeoffs, or irreversible changes).

### Compatibility & migrations (released project)

* You MUST maintain backwards compatibility with existing/old data.
* Database schema changes MUST be done via additive migrations (do NOT edit already-applied migration files).
* When introducing new fields, prefer nullable columns and safe defaults; handle missing/legacy values in application code.

## 2) Language & Communication

* User-facing chat responses: use the same language as the user’s request.
* Repository artifacts (code comments, docs, commit messages, logs, error messages): MUST be in English.

## Documentation (Fumadocs)

* All documentation lives under `content/docs` and is rendered by Fumadocs.
* Add new guides as `.mdx` files in `content/docs` and keep README short with links to docs.
* When migrating or updating docs, move long-form content out of README into Fumadocs.

## 3) Correctness Bar (No stubs / no shortcuts)

Never ship simplified, stubbed, placeholder, or “temporary” implementations.

This is especially strict for:

* Authentication & authorization
* Cryptography / key management / JWT / JWKS
* OAuth and WebAuthn/passkeys
* Protocol compatibility (wire formats, redirects, cookies)

Requirements:

* Match intended behavior exactly, including edge cases.
* No TODO stubs, no placeholder returns, no “just for now” workarounds.
* Handle errors fully and consistently; include actionable English error messages.

## 4) Verification (Build/Check)

Do not consider a change complete until it is verified.

* Rust: after any Rust change, run `cargo check --all-targets`.
* Rust (Workers/wasm): also run `cargo build -p beacon-worker --target wasm32-unknown-unknown` (or an equivalent command required by the change) to ensure Cloudflare Worker builds stay green.
* Avoid local `--release` builds.
* Use debug-mode builds only when needed for additional validation (e.g., `cargo build --all-targets`).

## 5) Testing Strategy

* Avoid running the full test suite locally unless you changed tests or the change has broad blast radius.
* Prefer fast validation first (e.g., `cargo check --workspace`) and then run only the relevant tests/modules when needed.

## 6) Dependency Management

* Rust: `cargo add -p <crate-name>`
* Node.js: prefer `pnpm add` in this repo (avoid introducing additional package managers).
* Python: `pip install` or `poetry add` depending on the project setup.

Before adding any new dependency/crate/package:

* MUST consult DeepWiki MCP for existing patterns/approved libraries.
* Justify why it is needed and why existing dependencies are insufficient.

## 7) Multi-language Workspace Rules (Rust + TypeScript/React + Gradle/Kotlin)

This repository is multi-language. When you touch one part, ensure the relevant toolchain still builds.

### Rust (server + shared crates)

* Source lives under `crates/`.
* Verification commands are defined in the "Verification (Build/Check)" section above.
* Do not add new crates lightly; consider optional features for platform-specific code (e.g., serverless).
* Distributed deployments: avoid per-process in-memory coordination for OAuth/Passkey start→finish unless you require sticky sessions.
* Ensure JWT/JWKS keys are stable across instances.

### TypeScript/React (Web UI)

* Frontend source lives under `src/` and uses `pnpm`.
* When backend API shape changes, update frontend calls/types in the same pass.
* Formatting/linting uses Biome (`biome.json`). Do not introduce a second formatter.
* All user-facing text MUST be localized via Paraglide (`@/paraglide/messages`). Do not hardcode UI copy in TSX/JS.
* When adding a new message key, update every locale file under `messages/` (at minimum: `en`, `de`, `fr`, `ja`, `ko`, `zh-Hans`, `zh-Hant`).
* This includes button labels, headings, helper text, validation errors, toast/status messages, tooltips, and `aria-*` labels.

### Gradle/Kotlin (Mod source)

* Source lives under `modSrc/`.
* Keep server-side protocol/auth changes compatible with the mod’s expectations (JWKS, redirect URLs, cookie/auth flow).
* Never hardcode secrets in Gradle files.

#### Minecraft login-flow invariants

These are business-logic constraints, not implementation details:

* `bypass_if_online_mode_verified = true` means Mojang online-mode verification wins. Do not intercept or short-circuit `handleHello` for online-mode players in a way that prevents vanilla/Mojang profile verification from completing.
* Vanilla premium clients without BeaconAuth must be able to join online-mode servers when Mojang verification succeeds and `bypass_if_online_mode_verified` is true.
* Modded premium clients must keep their Mojang-verified `GameProfile`/UUID when the same bypass is enabled; do not replace it with an offline placeholder or BeaconAuth stable UUID.
* Reflection/accessor/mixin compatibility fixes must be scoped to field/method access. They must not alter the authentication decision tree unless the user explicitly asks for a behavior change.
* Only force online-mode players into BeaconAuth when `bypass_if_online_mode_verified` is false. If this invariant appears to conflict with a null-profile or loader NPE fix, stop and ask before changing login behavior.

## 9) Cross-cutting Operational Rules

* Prefer configuration via environment variables or CLI flags.
* Keep HTTP app construction reusable for serverless targets; gate serverless-only code behind Cargo features and `required-features` binaries.
