#!/usr/bin/env node
// test/interop/run-peer-matrix.mjs
//
// `test/interop/docker-compose.yml` で起動したピア間の VC 発行・検証を実行する。
//
// 前提: `docker compose -f test/interop/docker-compose.yml up -d --build` 済みで、
// 各ピアのポートがホストへ公開されていること（ポート番号は run ごとに Docker が割り当て、
// ランナーが `docker compose port` で引く）。
//
// 出力: `{ generatedAt, results: Array<PairResult> }` を JSON で stdout に書く
// （`generate-report.mjs` の入力形式）。
//
// PairResult:
//   - pair: "interop:<issuer>:<verifier>"
//   - status: "pass" | "fail" | "skipped" | "known-incompatible"
//     （known-incompatible は `pairs.json` の `knownIncompatible` に登録済みの非互換が、登録どおりの
//     理由で fail した場合のみ。fail ではないので終了コードに影響せず、Issue も自動起票しない。
//     登録ペアの想定外の pass / 登録外の理由の fail は fail のまま。lib/known-incompatible.mjs）
//   - reason: fail/skipped/known-incompatible の場合の理由（人間可読）

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { isMainModule } from '../../scripts/lib/is-main-module.mjs';
import { resolvePeerBaseUrls } from './lib/host-ports.mjs';
import { applyKnownIncompatible } from './lib/known-incompatible.mjs';
import {
  checkPeerAlive,
  issueFromNativePeer,
  issueFromUniformPeer,
  runWaltidProtocol,
  verifyWithNativePeer,
  verifyWithUniformPeer,
} from './lib/peer-clients.mjs';
import { appendJobSummary, evaluateMatrix, formatStatusSummary } from './lib/skipped-gate.mjs';

const CONFIG = JSON.parse(readFileSync(new URL('./pairs.json', import.meta.url), 'utf8'));

/**
 * マトリクス全体を実行する。既定では実ピア（`pairs.json`）へ実 HTTP / `bun` サブプロセスで
 * 到達するが、`fetchImpl` / `spawnImpl` / `config` / `env` を差し替えることで、外部ピア無しに
 * 結果マッピング・pass/fail 判定ロジックを単体テストできる。
 */
export async function run({
  config = CONFIG,
  fetchImpl = fetch,
  spawnImpl = spawnSync,
  env = process.env,
} = {}) {
  const results = [];
  const { waltidProtocolPeers } = config;
  // ホストポートは run ごとに Docker が割り当てるので、`pairs.json` の `service` / `containerPort` から
  // `docker compose port` が返す実ポートで `baseUrl` を組み立てる。walt.id のプロトコル層
  // ピアは compose ネットワーク内のアドレスを使うため対象外。
  const uniformPeers = resolvePeerBaseUrls(spawnImpl, config.uniformPeers);
  const nativePeers = resolvePeerBaseUrls(spawnImpl, config.nativePeers);
  const externalPrerequisitePeers = resolvePeerBaseUrls(
    spawnImpl,
    config.externalPrerequisitePeers,
  );

  // 1. uniform × uniform（自己ペア含む）— VC 発行 → 検証の完全なラウンドトリップ。
  for (const issuer of uniformPeers) {
    let jwt;
    try {
      jwt = await issueFromUniformPeer(fetchImpl, issuer);
    } catch (error) {
      for (const verifier of uniformPeers) {
        results.push({
          pair: `interop:${issuer.name}:${verifier.name}`,
          status: 'fail',
          reason: `issue failed: ${error.message}`,
        });
      }
      continue;
    }
    for (const verifier of uniformPeers) {
      try {
        const { verified, error } = await verifyWithUniformPeer(fetchImpl, verifier, jwt);
        results.push({
          pair: `interop:${issuer.name}:${verifier.name}`,
          status: verified ? 'pass' : 'fail',
          reason: verified ? undefined : (error ?? '検証が verified=false を返した'),
        });
      } catch (error) {
        results.push({
          pair: `interop:${issuer.name}:${verifier.name}`,
          status: 'fail',
          reason: String(error),
        });
      }
    }
  }

  // 2. uniform（発行）× native（didkit/sphereon、ネイティブ VC-API で検証）。
  for (const issuer of uniformPeers) {
    let jwt;
    try {
      jwt = await issueFromUniformPeer(fetchImpl, issuer);
    } catch (error) {
      for (const native of nativePeers) {
        results.push({
          pair: `interop:${issuer.name}:${native.name}`,
          status: 'fail',
          reason: String(error),
        });
      }
      continue;
    }
    // native ごとに try/catch を分け、後段の通信例外で前段の pass と fail が同一ペアに
    // 二重記録されないようにする。
    for (const native of nativePeers) {
      const pair = `interop:${issuer.name}:${native.name}`;
      try {
        const { verified, error } = await verifyWithNativePeer(fetchImpl, native, jwt);
        results.push({
          pair,
          status: verified ? 'pass' : 'fail',
          reason: verified ? undefined : (error ?? '検証が verified=false を返した'),
        });
      } catch (error) {
        results.push({ pair, status: 'fail', reason: String(error) });
      }
    }
  }

  // 3. native（発行、LD-Proof）× 自己検証 / uniform（検証）。native ピアごとに
  //    `issueFromNativePeer` を 1 回だけ呼び（HTTP を増やさない）、その VC を (a) 同じピアの
  //    `/credentials/verify`（往復が成功した場合だけ pass）と (b) 各 uniform ピアの
  //    `POST /vc/verify` へ送る。(b) は uniform アダプタの入口検査がコンパクト JWT-VC 文字列しか
  //    受理しないため恒常的に落ちるが、決め打ちの `skipped`（ピアが落ちていても変わらず「試された」
  //    証拠にならない）ではなく**実際に試行**し、`pairs.json` の `knownIncompatible` で扱う
  //    （理由一致は `known-incompatible`、想定外の pass は `unexpected-pass`）。
  for (const native of nativePeers) {
    const selfPair = `interop:${native.name}:${native.name}`;
    let credential;
    try {
      credential = await issueFromNativePeer(fetchImpl, native, native.issuerDid);
    } catch (error) {
      // 発行できなければ自己ペアも uniform 2 ペアも fail で出す（黙って結果から落とさない）。
      // 理由が `knownIncompatible` の登録文言と違うので `known-incompatible` には畳まれない。
      results.push({
        pair: selfPair,
        status: 'fail',
        reason: `self-issue failed: ${error.message}`,
      });
      for (const verifier of uniformPeers) {
        results.push({
          pair: `interop:${native.name}:${verifier.name}`,
          status: 'fail',
          reason: `issue failed: ${error.message}`,
        });
      }
      continue;
    }
    try {
      const { verified, error } = await verifyWithNativePeer(fetchImpl, native, credential);
      results.push(
        verified
          ? { pair: selfPair, status: 'pass' }
          : { pair: selfPair, status: 'fail', reason: `self-verify failed: ${error}` },
      );
    } catch (error) {
      results.push({ pair: selfPair, status: 'fail', reason: `self-verify failed: ${error}` });
    }
    // uniform ごとに try/catch を分け、後段の通信例外が前段の結果と混ざらないようにする（section 1 と同形）。
    for (const verifier of uniformPeers) {
      const pair = `interop:${native.name}:${verifier.name}`;
      try {
        const { verified, error } = await verifyWithUniformPeer(fetchImpl, verifier, credential);
        results.push({
          pair,
          status: verified ? 'pass' : 'fail',
          reason: verified ? undefined : (error ?? '検証が verified=false を返した'),
        });
      } catch (error) {
        results.push({ pair, status: 'fail', reason: String(error) });
      }
    }
  }

  // 4. walt.id（OID4VCI/OID4VP）は Offer→Receive→Present の実プロトコル層を自動化する
  //    （run-waltid-protocol.mjs へ委譲）。
  results.push(...runWaltidProtocol(spawnImpl, waltidProtocolPeers));

  // 5. 外部前提（EBSI サンドボックス）が未設定ならスキップとして報告する。
  for (const peer of externalPrerequisitePeers) {
    if (!env[peer.requiresEnv]) {
      results.push({
        pair: `interop:${peer.name}:prerequisite`,
        status: 'skipped',
        reason: `prerequisite-missing: 環境変数 ${peer.requiresEnv} が未設定（${peer.note}）`,
      });
      continue;
    }
    // ホストポートを解決できていないピアは既定ポートへ戻さず fail にする。
    const alive =
      peer.unresolved === undefined &&
      (await checkPeerAlive(fetchImpl, peer.baseUrl, peer.healthPath ?? '/'));
    results.push({
      pair: `interop:${peer.name}:smoke`,
      status: alive ? 'pass' : 'fail',
      reason: alive ? undefined : (peer.unresolved ?? `${peer.name} プロキシが応答しなかった`),
    });
  }

  return {
    generatedAt: new Date().toISOString(),
    results: applyKnownIncompatible(results, config.knownIncompatible),
  };
}

/**
 * CLI 本体。結果 JSON を stdout（`generate-report.mjs` の入力形式）へ、
 * 内訳を Job Summary へ書き、終了コードを返す。
 *
 * `--fail-on-skipped` を付けた厳格モードでは、
 * **許可リストを持たず**、`skipped` が 1 件でもあれば終了コードを非 0 にする。
 * 構造的に落ちる native 発行 × uniform 検証の 4 ペアは `skipped` をやめて実際に試行し、
 * `knownIncompatible` で扱うため、ここで許容すべき `skipped` は無い。
 * Nightly は引数なしで呼ぶので終了コードの判定は従来どおり `fail` のみ。
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
  appendJobSummary(formatStatusSummary('Interop VC 発行・検証マトリクス', output.results), env);
  // 厳格モードは許可リストを渡さない（VC マトリクスに構造的な `skipped` は残っていない）。
  const { violations, exitCode } = evaluateMatrix(output.results, {
    strict: argv.includes('--fail-on-skipped'),
  });
  for (const violation of violations) error(`::error::${violation}`);
  return exitCode;
}

// テストから import できるよう、CLI から直接実行した場合だけ main() を呼ぶ。
if (isMainModule(import.meta.url)) {
  process.exitCode = await main();
}
