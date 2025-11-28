# General AI Coding Guidelines

> **This is a reusable instruction file that can be applied to any project.**

## 1. Communication Guidelines

* **User Communication:** When responding to users, use the **same language as the user's request** for better understanding.
* **Code Output:** All code content (comments, documentation, commit messages, console logs) **MUST** be written in **English** for consistency.

## 2. Code Verification (CRITICAL)

* **After modifying any code**, you **MUST** run the appropriate verification command before completing your task:
    * **Rust**: `cargo check --workspace` or `cargo build --workspace`
    * **TypeScript/JavaScript**: `pnpm typecheck` or `tsc --noEmit`
    * **Kotlin/Gradle**: `./gradlew build`
    * **Python**: `mypy` or `pyright` if configured
* Never consider a code modification complete without verification.

## 3. Git Change Synchronization (CRITICAL)

* **Before summarizing completed changes**, you **MUST** read git changes using `get_changed_files` tool.
* **After reviewing git changes**, update relevant documentation files to reflect any new patterns, endpoints, architecture changes, or workflows discovered in the changes.
* This ensures documentation stays synchronized with actual implementation.

## 4. Library Usage Research (CRITICAL)

* **Before using any external library**, you **SHOULD** use available tools (e.g., DeepWiki MCP server, official documentation) to query the correct usage patterns, API methods, and best practices.
* Query format: Use `mcp_cognitionai_d_ask_question` with the repo name (e.g., `"tokio-rs/tokio"`, `"tanstack/query"`) and a specific question about usage.
* This ensures you're using the latest API correctly and avoiding deprecated or incorrect patterns.

## 5. Project Synchronization (CRITICAL)

* **After making major changes** to the project (new features, architecture changes, API modifications, build system updates), you **MUST** synchronize documentation:
    * Update **instruction files** with new patterns, endpoints, or workflows.
    * Update the **README.md** with user-facing changes, setup instructions, or API documentation.
    * Update **CI/CD workflows** (e.g., `.github/workflows/*.yml`) if build processes, dependencies, or deployment steps change.
* This ensures consistency across documentation, AI guidance, and automation.

## 6. Best Practices

### Dependency Management
* Always use the appropriate package manager for the project:
    * **Node.js**: `pnpm add`, `npm install`, or `yarn add`
    * **Rust**: `cargo add -p <crate-name>`
    * **Python**: `pip install` or `poetry add`
    * **Gradle**: Add to `build.gradle.kts` dependencies block

### Error Handling
* Always handle errors gracefully with meaningful error messages.
* Use typed errors where possible (Result types, custom exceptions).
* Log errors with sufficient context for debugging.

### Code Style
* Follow the project's established coding conventions.
* Use consistent naming conventions (camelCase, snake_case, etc.) as per language standards.
* Keep functions/methods focused and single-purpose.

### Testing
* Write tests for new functionality when test infrastructure exists.
* Ensure existing tests pass before completing work.

### Security
* Never hardcode secrets, API keys, or passwords.
* Use environment variables or secure configuration for sensitive data.
* Validate and sanitize user inputs.
