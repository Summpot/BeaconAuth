# Instructions for Summpot/BeaconAuth

## 0. Task Execution Philosophy

* **Complete tasks in a single pass whenever possible.** No need to break work into multiple incremental steps.
* When a task involves multiple related changes, complete ALL of them together.
* **Integration over isolation**: When implementing a new module, also integrate it into existing code, update imports, and handle any resulting compilation errors - all in one go.
* Only request user confirmation when genuinely uncertain, not for every intermediate step.

## 1. Communication Guidelines

* **User Communication:** Use the **same language as the user's request**.
* **Code Output:** All code content (comments, documentation, commit messages, console logs) **MUST** be in **English**.

## 2. Code Verification
* **After modifying any code**, run the appropriate verification command:
    * **Rust**: `cargo check --all-targets`.
* Never consider a code modification complete without verification.
* **NEVER use `--release` flag for local builds** - release builds are slow and unnecessary for development.
* Use `cargo build --all-targets` (debug mode) for local validation.
* Release builds are only for CI/CD pipelines.

## 3. Testing Strategy

* **Avoid running all tests locally** unless:
    * You modified the tests themselves.
    * Your changes have obvious breaking potential.
* Use `cargo check --workspace` for quick validation instead of full test runs.
* When tests are necessary, run only relevant test modules.

## 4. Library Usage Research

* **Before using any external library**, use available tools to query usage patterns.
* Recommended: Use `mcp_cognitionai_d_ask_question` (DeepWiki MCP) with the repo name.
* **If DeepWiki lacks documentation**: Record the issue and proceed with best knowledge.
* Do NOT use `cargo doc --open` to generate documentation locally.

## 5. Prohibition of Simplified Implementations

**NEVER use simplified, stub, placeholder implementations, or temporary fixes.** This includes:

* **Language migration projects** (e.g., Go to Rust).
* **Protocol implementations** requiring wire-compatibility.
* **Security-critical code** (cryptography, authentication, access control).
* **Match original behavior exactly**: Replicate original logic, error handling, and edge cases.
* **No TODO stubs**: Do not leave unimplemented functions or placeholder returns.
* **No temporary workarounds**: Always implement the complete, correct solution.
* **Complete error handling**: Handle all error cases the same way as the reference implementation.
* **Full feature parity**: Implement all features, not just the "common" ones.
* **Research thoroughly**: Understand the full complexity before implementing.
* **Port completely**: Translate ALL logic including edge cases.
* **Split large tasks**: Create a detailed plan with specific milestones rather than implementing a partial version.

## 6. Best Practices

### Dependency Management
* **Rust**: `cargo add -p <crate-name>`.
* **Node.js**: `pnpm add`, `npm install`, or `yarn add`.
* **Python**: `pip install` or `poetry add`.

### Error Handling
* Handle errors gracefully with meaningful error messages.
* Use typed errors where possible (Result types, custom exceptions).
* Log errors with sufficient context for debugging.

### Code Style
* Follow the project's established coding conventions.
* Use consistent naming conventions as per language standards.
* Keep functions/methods focused and single-purpose.

## 7. Multi-language Workspace Rules (Rust + TypeScript + Gradle/Kotlin)

This repository is multi-language. Changes often span multiple toolchains. When you touch one part, verify the relevant part(s) still build.

### 7.1 Rust (Auth server + shared crates)

* Source lives under `crates/`.
* Preferred validation:
    * Fast: `cargo check --workspace`
    * Full targets: `cargo check --all-targets` (required after any Rust change)
* Do not add new crates lightly. If you add one:
    * Justify why it is needed.
    * Keep it optional behind a feature when it is platform-specific (e.g., serverless).
* Security-sensitive changes (JWT, OAuth, WebAuthn):
    * Avoid stateful in-memory coordination that breaks multi-instance deployments.
    * Prefer stateless, signed tokens/cookies or persistent storage.

### 7.2 TypeScript/React (Web UI)

* Source lives under `src/` (frontend) and uses `pnpm`.
* When backend API shape changes, update frontend calls/types in the same pass.
* Formatting/linting uses Biome configuration (`biome.json`). Do not introduce a second formatter.

### 7.3 Gradle/Kotlin (Mod source)

* Source lives under `modSrc/` with Gradle (Kotlin DSL).
* Keep server-side protocol changes compatible with the mod’s expectations (JWKS, redirect URLs, cookie/auth flow).
* Do not hardcode secrets in Gradle files.

### 7.4 Cross-cutting rules

* Always keep code comments, logs, and error messages in **English**.
* Prefer configuration via environment variables / CLI flags.
* For distributed deployments:
    * Do not rely on per-process memory for OAuth/Passkey start→finish unless you require sticky sessions.
    * Ensure JWT/JWKS keys are stable across instances.
* For serverless targets:
    * Keep the HTTP app construction in reusable library functions.
    * Gate serverless-only code behind Cargo features and `required-features` binaries.