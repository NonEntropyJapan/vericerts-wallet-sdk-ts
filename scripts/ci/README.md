# SDK validation tools

Run commands from the SDK root with Node 20.19.0 or later and the Bun version in
`.bun-version`. Install this checkout's exact development dependencies first:

```sh
bun install --frozen-lockfile
bun run ci:profile --profile=static
bun run ci:profile --profile=unit
bun run ci:profile --profile=conformance
```

`static` checks formatting, types, all three generated schemas, source module
boundaries and Critical dependency advisories. Lower severity advisories remain
visible in the audit output. A failed audit or malformed report fails validation.

`unit` runs the explicit tracked source-test manifest, requires every file to
produce cases, rejects skip/todo/failure/zero results, then checks source coverage:
80% overall and 95% for `src/internal/keymanager/`. With `--base=<exact SDK SHA>`,
added source lines must reach 90%. Unloaded tracked executable source still counts
as uncovered. Test and packaged Interop results cannot improve source coverage.

`conformance` executes and checks all five VC, PE, HAIP, OID4VCI and OID4VP suites.
`node` checks source types, builds, and runs ESM/CJS distribution smoke tests.

The four `scripts/check-*.mjs` gates and their shared closure belong to this SDK.
They support JS/TS and Bun JUnit only. Their parsers load exact tooling from this
checkout's own `node_modules`; another checkout or `NODE_PATH` cannot provide it.
JUnit is validated as a complete XML document with the development dependency
`fast-xml-parser`. The accepted Bun protocol requires a `testsuites` root with a
numeric `tests` count, suites and named/file-bound cases. Comments/CDATA are inert;
DTD and document-defined entities are rejected. This is deliberately narrower
than a general JUnit implementation.

The module-boundary check resolves static imports, type imports, import-equals,
reference paths and literal module loads. It follows standard Node createRequire
factory/namespace/loader aliases with TypeScript binding information, checks the
factory anchor, and rejects unresolved loads and escaping loader capabilities. Its explicit distribution probes are the ESM
and CJS smoke scripts, the package runtime and contained TypeScript loaders,
Node consumer hooks, optional-peer checks, the synthetic browser boundary-control
resolver, the NOTICE metadata resolver and the two verified public fixture tools.
Each exception is a specific file/expression; other loads in that file still pass
normal validation. NOTICE input, package, resolver-result and license realpaths
must remain within the SDK (package files within its own node_modules). Their
runtime containment is checked separately; this scan is not a general file-system
sandbox.

The same check validates TypeScript config paths, including inherited settings
and project references, and checks the real paths of files in the TypeScript
program before reading them. Specify `extends` as an explicit file inside the
SDK. Type and package resolution use the SDK's own installed dependencies.

## Registry dependency policy

The exact development dependency `semver` parses semver ranges. The surrounding
policy accepts a deliberately narrow registry-only grammar without Git/URL
resolution or fetching. Accepted values are registry versions,
constrained semver ranges, dist-tags and npm aliases with an explicit constrained
registry range or tag. Empty/unbounded wildcard alternatives and aliases with an
omitted or wildcard range are rejected. Arbitrary URI schemes and local, Git,
workspace, catalog or tarball sources cannot fall through as unknown syntax.

The policy checks dependencies, devDependencies, peerDependencies,
optionalDependencies, nested overrides/resolutions, pnpm.overrides and dependency
fields injected by pnpm.packageExtensions. Package names must use canonical lowercase ASCII npm names. Tags use ASCII
letters/digits/dot/underscore/hyphen, start with a letter and cannot be archive
filenames. Replacement selectors must be package-name/version selectors; unsupported manager-specific selectors fail.
Override `$name` references select a validated direct declaration, never another
replacement, so dangling references or reference cycles cannot resolve. Workspace,
catalog and bundling metadata are outside this standalone checkout's scheme.

## Isolated source validation

`node scripts/ci/run-isolated.mjs --profile=unit` requires a clean checkout. It
creates a temporary SDK-only Git repository with an arbitrary directory name,
without source history, remotes, ancestor configuration or credentials. A base
commit is projected to its SDK tree; source-tree diffs and projected diffs must
match. Child processes receive normalized working-directory variables and a small
allowlist of environment variables. The source must not change while validating.

The temporary projection mapping stays outside the SDK source. It is local QA
material. Its synthetic revision and receipts have `private-validation` context
and `publicRevision: null`; they do not establish public release provenance.

`execution-manifest.json` lists every tracked SDK test file. Source tests and
`test/interop/` package tests form disjoint suites. The CI unit profile produces
`source-suite-result.json`. The same job then downloads the build job's tarball
and receipt by artifact ID and runs `scripts/ci/package-interop.mjs` against that
artifact in an independent consumer. The package runner executes the six Interop
groups and the internal loop, validates case identity, and produces
`package-interop-result.json` and `suite-union-result.json`.

The proof upload includes the manifest, result fragments and raw Interop reports
under `coverage/interop/`, including Bun JUnit and Node TAP and JSONL. Candidate
aggregation installs the pinned SDK proof tooling, re-reads the raw reports,
and verifies the full file union, case identities, projected source, tarball
SHA-256 and SRI, and receipt hash.

## Local source and package tests

Use Node 24 and the Bun version from `.bun-version` for the complete suite:

```sh
bun run test
bun run test:coverage
node scripts/ci/test.mjs --input=committed
```

`bun run test` and `bun run test:coverage` copy the current SDK inputs, including
tracked edits and non-ignored files, into a temporary development snapshot.
`--input=committed` requires a clean SDK subtree and validates a projection of
the current commit. Both inputs use one local tarball for the packaged Interop
suite and check for source changes before completing. The coverage command
applies SDK source thresholds to the source run. Local evidence is saved under
`coverage/sdk-suite-*/` with `local-suite` validation. For interactive work,
`bun run test:watch` runs the source test list. Restart it after adding or deleting
a test file.

## Workflow template

`.github/workflows/ci.yml` is the portable SDK-root CI template. It uses hosted
runners and read-only permissions. Its five SDK jobs feed a candidate aggregate;
other repositories' build jobs are not prerequisites. After the projected SDK
install, `node scripts/ci/prepared.mjs browser` installs Chromium using the SDK's
locked browser fixture and records `PLAYWRIGHT_BROWSERS_PATH` for the CI producer.
The producer checks one tarball sequentially with Node 24, Bun, both browser peer
modes, Node 20.19.0 and Node 22, then runs the guarded npm publish dry-run. Dedicated
Node jobs additionally preserve the source type/build/dist contracts.

The candidate's schema v2 receipt requires `committed-projection` origin and
records `publicRevision: null`. Workflow uploads retain validation artifacts in
Actions. Package validation and publish dry-run leave the registry unchanged.
See [packed consumer](../packed-consumer/README.md) for artifact and receipt commands.
