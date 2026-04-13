# Contributing to Privasys ID

Thank you for your interest in contributing! This monorepo contains the Privasys ID mobile app, the `@privasys/auth` browser SDK, and the authentication broker.

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

If you find a bug or have a suggestion, please [open an issue](https://github.com/Privasys/privasys-id/issues).

## License

By contributing, you agree that your contributions will be licensed under the [GNU Affero General Public License v3.0](LICENSE).
