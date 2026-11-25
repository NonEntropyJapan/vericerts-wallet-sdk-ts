# TypeScript SDK development

- Keep the library independent of browser extensions, applications, and other repositories. Accept platform-specific storage, network, and signing behavior through the SDK's interfaces.
- Treat the entry points in `package.json` under `exports` as the public API. Keep application consumers on those entry points and preserve the documented behavior of existing APIs.
- Use the JSDoc maturity markers `@stable`, `@experimental`, `@deprecated`, and `@internal`. Before 1.0, unmarked exports are experimental.
- Exercise changes to the public API through package entry points. Keep test data and build inputs self-contained within this repository.
- Announce deprecations in [CHANGELOG.md](CHANGELOG.md) and mark the API with `@deprecated`. Allow at least two minor releases or six months, whichever is longer, before removing a stable API in a major release.
- Release the SDK before updating downstream consumers to use a new API.
- Follow the local checks and contribution process in [CONTRIBUTING.md](CONTRIBUTING.md).
