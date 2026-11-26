# VeriCerts Wallet SDK

TypeScript SDK for decentralized identifiers, verifiable credentials, and OpenID credential issuance and presentation.

## Install

The SDK requires Node.js 20.19.0 or later. The npm install command is available after the first npm release.

```sh
npm install @vericerts/vericerts-wallet-sdk
```

The package exposes typed entry points for common utilities, identity, credentials, issuance, and presentation. Import from an entry point listed in `package.json` under `exports`.

```ts
import { ErrorCodes } from '@vericerts/vericerts-wallet-sdk/common';
```

## Develop

Use Node.js 24 and the Bun version pinned in `.bun-version`.

```sh
bun install --frozen-lockfile
bun run check
bun run typecheck
bun run test
```

## Release publisher

VeriCerts株式会社 publishes the VeriCerts Wallet SDK.
Git release tags in this repository use the package version with a `v` prefix.
For example, the tag for package version `0.1.0` is `v0.1.0`.

## License

[Apache License 2.0](LICENSE).
