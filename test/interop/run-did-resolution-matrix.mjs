#!/usr/bin/env node
// test/interop/run-did-resolution-matrix.mjs
//
// DID 解決マトリクスを `test/interop/docker-compose.yml` の実ピアに対して実行する。
// `pairs.json` の 18 セルを `contracts/matrix.json` の公開契約に照らして検証する。
//
// なぜ VC 発行・検証ランナー（run-peer-matrix.mjs）と分けるか: 失敗理由（解決器の未提供・fixture の
// 未整備・外部サンドボックスの前提）も、外部依存（チェーン / HTTPS ホスト / EBSI 登録）も、
// リリースゲートでの扱いも VC マトリクスとは異なる。同じランナーに混ぜると、どちらかの都合での
// skip が他方の失敗を隠す。結果形式だけを共有し、実行単位を分離する。
//
// 前提: `docker compose -f test/interop/docker-compose.yml up -d --build` 済みで、各ピアのポートが
// ホストへ公開されていること（ポート番号は run ごとに Docker が割り当て、ランナーが
// `docker compose port` で引く）。
//
// 出力: `{ generatedAt, results: Array<PairResult> }` を JSON で stdout に書く
// （`generate-report.mjs` の入力形式）。
//
// PairResult:
//   - pair: "interop:did-resolve:<method>:<peer>"（<method> は key / web / ethr / jwk / ebsi）
//   - status: "pass" | "fail" | "skipped" | "known-incompatible"
//     （known-incompatible は `pairs.json` の `knownIncompatible` に登録済みの非互換が、登録どおりの
//     理由で fail した場合のみ。lib/known-incompatible.mjs）
//   - reason: fail/skipped/known-incompatible の場合の理由（人間可読）
//
// ピア未起動・タイムアウトは skipped ではなく fail にする。skipped にすると Issue 自動起票の対象外で、
// 解決が一度も走らないまま Nightly が緑になる。

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { isMainModule } from '../../scripts/lib/is-main-module.mjs';
import {
  findVerificationMethodWithKey,
  resolveDidWithPeer,
} from './lib/did-resolution-clients.mjs';
import { resolvePeerBaseUrls } from './lib/host-ports.mjs';
import { applyKnownIncompatible } from './lib/known-incompatible.mjs';
import { appendJobSummary, evaluateMatrix, formatStatusSummary } from './lib/skipped-gate.mjs';

const CONFIG = JSON.parse(readFileSync(new URL('./pairs.json', import.meta.url), 'utf8'));

const skipped = (reason) => ({ status: 'skipped', reason });
const failed = (reason) => ({ status: 'fail', reason });

/**
 * fixture 1 件分（`{ did, expectedKey? }`）をピアに解決させる。
 *
 * `expectedKey` を持つ fixture（did:key / did:jwk のように DID 自体が公開鍵を含むメソッド）では、
 * 解決結果の検証鍵が**要求した DID から導かれる鍵**と一致することまで確かめる。これが無いと、
 * `id` だけ合っていて無関係な鍵を返す解決器が pass する。
 */
async function resolveFixture(fetchImpl, peer, fixture) {
  const { resolved, didDocument, error } = await resolveDidWithPeer(fetchImpl, peer, fixture.did);
  if (!resolved) {
    return { resolved: false, error };
  }
  if (fixture.expectedKey && !findVerificationMethodWithKey(didDocument, fixture.expectedKey)) {
    return {
      resolved: false,
      error: `verification-method-mismatch: ${fixture.did} から導かれる公開鍵と一致する検証鍵が解決結果の DID Document に無い`,
    };
  }
  return { resolved: true };
}

/**
 * did:ethr を EIP-1056 registry の版ごとに解決する（`pairs.json` の `fixtures.ethr.eip1056Versions`）。
 *
 * **全版が成功したときだけ pass にする**。単一の固定版が通っただけでは「複数版対応」と見なさない。
 * 1 版でも落ちれば fail とし、落ちた版の識別子と理由を列挙する。
 * 全版が fixture 未整備なら、実行していない事実を skipped として版ごとの理由付きで報告する
 * （一部だけ未整備の場合は「全版成功」ではないので fail に倒す）。
 */
async function resolveEip1056Versions(fetchImpl, peer, versions) {
  if (versions.length === 0) {
    return failed('fixture-invalid: eip1056Versions が空（複数版の fixture が定義されていない）');
  }
  if (versions.every((version) => typeof version.unavailable === 'string')) {
    const reasons = versions.map((v) => `${v.version}: ${v.unavailable}`).join(' / ');
    return skipped(`fixture-missing: ${reasons}`);
  }
  const failures = [];
  for (const version of versions) {
    if (typeof version.unavailable === 'string') {
      failures.push(`${version.version}: fixture-missing: ${version.unavailable}`);
      continue;
    }
    const { resolved, error } = await resolveFixture(fetchImpl, peer, version);
    if (!resolved) {
      failures.push(`${version.version}: ${error}`);
    }
  }
  if (failures.length > 0) {
    return failed(`eip1056-version-failed: ${failures.join(' / ')}`);
  }
  return { status: 'pass' };
}

/**
 * ペア 1 件（メソッド × ピア）の結果を決める。
 *
 * 判定は次の順で、最初に当たったものを返す（理由は必ず付ける）。順序を変えると、たとえば
 * EBSI ピアが「環境変数が未設定」ではなく「fixture 未整備」として報告され、運用側の前提が
 * 整った後も理由が変わらないまま誤解を生む。
 *   1. ピアが解決経路を公開していない → skipped (resolver-unavailable)
 *   2. ピアの外部前提（環境変数）が未設定 → skipped (prerequisite-missing)
 *   3. ホストポートを解決できなかった → fail (host-port-unresolved。既定ポートへ戻さない)
 *   4. メソッドの fixture が未整備 → skipped (fixture-missing)
 *   5. did:ethr（複数 EIP-1056 版）→ 全版を解決して判定
 *   6. 上記以外 → 実解決。解決できたときだけ pass
 */
async function resolvePair({ fetchImpl, env, method, peer, fixture }) {
  if (peer === undefined) {
    return failed(`config-invalid: ${method} のピアが pairs.json の didResolution.peers に無い`);
  }
  if (typeof peer.unavailable === 'string') {
    return skipped(`resolver-unavailable: ${peer.unavailable}`);
  }
  if (peer.requiresEnv && !env[peer.requiresEnv]) {
    return skipped(
      `prerequisite-missing: 環境変数 ${peer.requiresEnv} が未設定（${peer.note ?? ''}）`,
    );
  }
  if (typeof peer.unresolved === 'string') {
    return failed(peer.unresolved);
  }
  if (fixture === undefined) {
    return failed(
      `config-invalid: ${method} の fixture が pairs.json の didResolution.fixtures に無い`,
    );
  }
  if (typeof fixture.unavailable === 'string') {
    return skipped(`fixture-missing: ${fixture.unavailable}`);
  }
  if (Array.isArray(fixture.eip1056Versions)) {
    return resolveEip1056Versions(fetchImpl, peer, fixture.eip1056Versions);
  }
  if (typeof fixture.did !== 'string') {
    return failed(`fixture-invalid: ${method} の fixture に解決対象の did が無い`);
  }
  const { resolved, error } = await resolveFixture(fetchImpl, peer, fixture);
  return resolved ? { status: 'pass' } : failed(error);
}

/**
 * DID 解決マトリクス全体を実行する。既定では実ピア（`pairs.json`）へ実 HTTP で到達するが、
 * `fetchImpl` / `config` / `env` を差し替えることで、外部ピア無しに判定ロジックを単体テストできる
 * （run-peer-matrix.mjs と同じ依存注入の作法）。
 *
 * `matrix` をメソッド順・ピア順に列挙し、各ペアはちょうど 1 回だけ結果を出す。
 */
export async function run({
  config = CONFIG,
  fetchImpl = fetch,
  spawnImpl = spawnSync,
  env = process.env,
} = {}) {
  const { matrix, fixtures } = config.didResolution;
  // ホストポートは run ごとに Docker が割り当てるので、`pairs.json` の `service` / `containerPort` から
  // `docker compose port` が返す実ポートで `baseUrl` を組み立てる。
  const peers = resolvePeerBaseUrls(spawnImpl, config.didResolution.peers);
  const results = [];
  for (const [method, peerNames] of Object.entries(matrix)) {
    for (const peerName of peerNames) {
      const outcome = await resolvePair({
        fetchImpl,
        env,
        method,
        peer: peers[peerName],
        fixture: fixtures[method],
      });
      results.push({ pair: `interop:did-resolve:${method}:${peerName}`, ...outcome });
    }
  }
  return {
    generatedAt: new Date().toISOString(),
    // レポートの「生成」欄に出す（`generate-report.mjs`）。VC マトリクスと同じ日に走るため、
    // どちらのランナーの結果かがレポート本文から分かるようにする。
    generator: 'test/interop/run-did-resolution-matrix.mjs',
    results: applyKnownIncompatible(results, config.knownIncompatible),
  };
}

/**
 * CLI 本体。`run-peer-matrix.mjs` の `main` と同じ契約で、`--fail-on-skipped` のときだけ
 * `didResolution.structuralSkips`（計 13 件）に無い `skipped` を失敗にする。
 *
 * EBSI の 2 ペア（`interop:did-resolve:web:ebsi` / `interop:did-resolve:ebsi:ebsi`）は許可リストに
 * `fixture-missing` で登録してある。`resolvePair` は `requiresEnv` を fixture より先に見るため、
 * 運用側が `EBSI_SANDBOX_BASE_URL` を用意するまでは同じ 2 ペアが `prerequisite-missing` になり、
 * **登録と違う理由**としてゲートが落ちる（運用前提の未充足を検知し続ける）。変数の登録後は
 * `fixtures.web.unavailable`（did:web の DID 文書ホスト）/ `fixtures.ebsi.unavailable`
 * （did:ebsi のテスト DID 未確定）による `fixture-missing` になり、登録どおりの理由として許容される。
 * どちらの fixture も環境変数の設定とは別に用意する。
 */
export async function main({
  argv = process.argv,
  runImpl = run,
  env = process.env,
  log = console.log,
  error = console.error,
} = {}) {
  const output = await runImpl();
  log(JSON.stringify(output, null, 2));
  appendJobSummary(formatStatusSummary('Interop DID 解決マトリクス', output.results), env);
  const { violations, exitCode } = evaluateMatrix(output.results, {
    strict: argv.includes('--fail-on-skipped'),
    structuralSkips: CONFIG.didResolution.structuralSkips,
  });
  for (const violation of violations) error(`::error::${violation}`);
  return exitCode;
}

// CLI から直接実行された場合だけ走らせる（`node --test` からの import では走らせない。
// run-peer-matrix.mjs と同じ方針）。
if (isMainModule(import.meta.url)) {
  process.exitCode = await main();
}
