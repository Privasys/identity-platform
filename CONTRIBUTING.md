# Contributing to Privasys Identity Platform

Thank you for your interest in contributing! This monorepo contains the Privasys Wallet mobile app, the `@privasys/auth` browser SDK, and the authentication broker.

## Getting Started

1. **Fork** the repository and clone your fork.
2. Install prerequisites:
   - [Bun](https://bun.sh/) 1.3+ (wallet & SDK)
   - [Go](https://go.dev/) 1.24+ (broker)
   - [Rust](https://rustup.rs/) stable (native RA-TLS module, optional for app-only changes)
3. Install dependencies:
   ```bash
   cd wallet && bun install
   cd ../sdk && bun install
   ```

## Project Structure

| Path | Language | Description |
|------|----------|-------------|
| `wallet/` | TypeScript / React Native | Expo mobile app |
| `wallet/modules/native-ratls/` | Swift / Kotlin / Rust | RA-TLS native module |
| `wallet/modules/native-keys/` | Swift / Kotlin | Secure key storage module |
| `sdk/` | TypeScript | Browser SDK (`@privasys/auth`) |
| `broker/` | Go | WebSocket relay service |

## Making Changes

- Keep commits focused: one logical change per commit.
- Write meaningful commit messages (e.g. `wallet: add batch auth flow`).
- Use `bunx tsc --noEmit` to type-check the wallet and SDK before pushing.
- Run `cd wallet && npx jest` to run the test suite.
- Use `go vet ./...` in the broker directory.
- Follow the existing code style in each sub-project.

## Submitting a Pull Request

1. Create a feature branch from `main`.
2. Make your changes and commit.
3. Push to your fork and open a Pull Request against `main`.
4. Describe what you changed and why.

## Reporting Issues

If you find a bug or have a suggestion, please [open an issue](https://github.com/Privasys/identity-platform/issues).

## Licence and Contributor Licence Agreement

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).

Before we can merge your first pull request, you need to accept the
[Privasys Contributor Licence Agreement](https://github.com/Privasys/cla). You
keep the copyright in your work; the agreement lets Privasys also license it
under other terms, and Privasys commits to keeping it available under an
open-source licence. A check on your pull request explains how to accept: one
comment, once, for every Privasys repository. If you contribute as part of your
work for an employer, your employer may need to sign the entity agreement
instead.
