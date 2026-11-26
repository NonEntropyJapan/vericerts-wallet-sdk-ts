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

## Publishing to npm

1. Take the validated artifact ID from a successful SDK validation push on `main`. Run downstream consumer tests on its tarball and record its SHA-256 and the full commit SHA.
2. On the same commit of `main`, run **Sign npm release candidate** with that artifact ID and the SHA-256 from the consumer tests. If the source changes or the artifact expires, use a fresh candidate and repeat the consumer checks.
3. Download the resulting `npm-release-<commit>-<attempt>` artifact into an empty directory. It contains the tested tarball and its Sigstore bundle. From that directory, set `REVISION`, `VERSION`, and `NPM_PUBLISHER` to the reviewed commit, package version, and authorized npm username. For a stable release, run the following in a shell with GitHub CLI and npm 11 or later.

```sh
(
  set -eu
  repo=NonEntropyJapan/vericerts-wallet-sdk-ts
  registry=https://registry.npmjs.org
  tarball="./vericerts-vericerts-wallet-sdk-${VERSION:?}.tgz"
  gh attestation verify "$tarball" --bundle provenance.json --digest-alg sha512 \
    --repo "$repo" --source-ref refs/heads/main --source-digest "${REVISION:?}" \
    --signer-workflow "$repo/.github/workflows/npm-provenance.yml" --deny-self-hosted-runners
  test "$(npm whoami --registry="$registry")" = "${NPM_PUBLISHER:?}"
  npm publish "$tarball" --registry="$registry" --access public --tag latest \
    --ignore-scripts --provenance-file=./provenance.json
)
```

After publishing, check `dist.integrity` and `dist.attestations` with `npm view @vericerts/vericerts-wallet-sdk@"$VERSION" dist --json`. Install that exact version in a clean project and run `npm audit signatures` to verify the registry signatures and provenance.
