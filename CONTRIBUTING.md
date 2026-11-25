# Contributing

Use the Bun version in `.bun-version` and Node.js 24 for local SDK development.

```sh
bun install --frozen-lockfile
bun run check
bun run typecheck
bun run test
```

Describe the change and the checks you ran in the pull request. For changes to a public API, include a test that exercises the package entry point. Keep test data, build steps, and documentation usable from a standalone SDK checkout.

Sign off commits with `git commit -s` to certify the [Developer Certificate of Origin](https://developercertificate.org/). SDK contributions are licensed under the [Apache License 2.0](LICENSE).
