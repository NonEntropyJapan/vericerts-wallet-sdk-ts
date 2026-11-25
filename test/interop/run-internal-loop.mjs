#!/usr/bin/env bun

// test/interop/run-internal-loop.mjs
//
// 外部ピア・Docker 不要の SDK 発行・検証ループ。パッケージの公開 API を使い、
// VC 発行 → 検証のラウンドトリップを直接呼び出す（HTTP アダプタ経由の
// `test/interop/adapters/vericerts/server.mjs` と同じロジックを使う）。
//
// 使い方: bun test/interop/run-internal-loop.mjs

import {
  createPrivateKeySigner as defaultCreatePrivateKeySigner,
  issueCredential as defaultIssueCredential,
  verifyCredential as defaultVerifyCredential,
} from 'vericerts-wallet-sdk/credential';
import { isMainModule } from '../../scripts/lib/is-main-module.mjs';

/**
 * SDK 自身による VC 発行 → 検証のラウンドトリップを 1 回実行し、`iss` クレームの一致を判定する。
 * `issueCredential` / `createPrivateKeySigner` / `verifyCredential` / `now` / `randomSeed` を
 * 差し替えることで、実 SDK 呼び出し無しに引数解釈・期待結果判定ロジックを単体テストできる
 * （`run-peer-matrix.mjs` の `fetchImpl`/`spawnImpl` DI と同じ方針）。
 *
 * @returns {{ ok: boolean, message: string }}
 */
export function run({
  issueCredential = defaultIssueCredential,
  createPrivateKeySigner = defaultCreatePrivateKeySigner,
  verifyCredential = defaultVerifyCredential,
  now = new Date(),
  randomSeed = crypto.getRandomValues(new Uint8Array(32)),
} = {}) {
  const signer = createPrivateKeySigner(randomSeed, 'EdDSA');
  const publicKeyJwk = signer.publicKeyJwk;

  const vc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:interop-internal-loop',
    credentialSubject: { id: 'did:example:interop-internal-loop-subject', name: 'internal-loop' },
    issuanceDate: now.toISOString(),
  };

  const jwt = issueCredential(vc, signer, { nowSeconds: Math.floor(now.getTime() / 1000) });
  const result = verifyCredential(jwt, { key: { publicKeyJwk } });

  if (result.payload.iss !== vc.issuer) {
    return {
      ok: false,
      message: `internal loop failed: issuer mismatch (${result.payload.iss} !== ${vc.issuer})`,
    };
  }

  return { ok: true, message: 'internal loop OK: issue -> verify round trip succeeded' };
}

/**
 * `run()` の判定結果を報告し、失敗時は非0で終了する。CLI エントリポイントと単体テストの
 * 両方から呼べるよう `log`/`error`/`exit` を DI する。
 */
export function reportAndExit(
  { ok, message },
  { log = console.log, error = console.error, exit = process.exit } = {},
) {
  if (ok) {
    log(message);
    return;
  }
  error(message);
  exit(1);
}

// CLI から直接実行された場合だけ走らせる（`bun test` からの import では走らせない。
// run-peer-matrix.mjs と同じ方針）。
if (isMainModule(import.meta.url)) {
  reportAndExit(run());
}
