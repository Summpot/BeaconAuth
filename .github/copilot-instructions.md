# BeaconAuth Monorepo - AI Guidance

> **Modular Instructions:** This file provides project-specific context. For detailed instructions, see the sub-instruction files in `.github/instructions/`.

## Instruction Files

| File | Description | When to Use |
|------|-------------|-------------|
| [general.instructions.md](instructions/general.instructions.md) | Universal coding guidelines (reusable across projects) | Always |
| [frontend.instructions.md](instructions/frontend.instructions.md) | React/Rsbuild frontend | Editing `src/`, `package.json` |
| [backend.instructions.md](instructions/backend.instructions.md) | Rust/Actix-web backend | Editing `crates/`, `Cargo.toml` |
| [minecraft-mod.instructions.md](instructions/minecraft-mod.instructions.md) | Kotlin/Architectury Minecraft mod | Editing `modSrc/` |

## 1. Our Goal

You are an AI assistant helping to build the **BeaconAuth** monorepo. Your task is to understand and correctly modify the three distinct projects within this repository:
1.  **The Frontend** (React/Rsbuild)
2.  **The Backend** (Rust/Actix-web API)
3.  **The Minecraft Mod** (Kotlin/Architectury/Gradle)

## 2. Core Monorepo Structure (CRITICAL)

This repository contains three projects with two different "root" concepts.

### Project 1: Root (Frontend & Backend)

* The **project root** directory contains the **React Frontend** (`package.json`, `rsbuild.config.ts`, `src/`) and the **Rust Backend** (`Cargo.toml`, `crates/`).
* This is the "main" project for web development.
* `cargo` and `pnpm` commands are run from here.

### Project 2: `modSrc/` (Minecraft Mod)

* The `modSrc/` directory is a **separate, self-contained Gradle project**.
* It contains all Kotlin Mod code (`common/`, `fabric/`, `forge/`) and its own build system (`build.gradle.kts`, `settings.gradle.kts`, `gradlew`).
* **To work on the Mod in an IDE, you MUST open the `modSrc/` directory as the project root.**

## 3. Quick Reference

### Dependency Management

| Project | Command | Location |
|---------|---------|----------|
| Frontend | `pnpm add <package>` | Root directory |
| Backend | `cargo add -p <crate-name> <dep>` | Root directory |
| Mod | Edit `build.gradle.kts` | `modSrc/` directory |

### Build Verification

| Project | Command |
|---------|---------|
| Frontend | `pnpm build` |
| Backend | `cargo check --workspace` |
| Mod | `./gradlew build` (from `modSrc/`) |