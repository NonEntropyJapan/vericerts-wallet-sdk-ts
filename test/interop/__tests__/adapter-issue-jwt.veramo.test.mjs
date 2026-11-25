// test/interop/__tests__/adapter-issue-jwt.veramo.test.mjs
//
// 実 Veramo（`@veramo/*` 公式パッケージ。モックなし）が Veramo アダプタ経由で発行した JWT-VC の JWS ヘッダに、
// `kid` が載り、その値が発行者の検証メソッド id（署名鍵を指す DID URL）と一致することの回帰テスト。
//
// `adapter-issue-jwt.test.mjs` の Veramo ケースはスタブ agent で呼び出し引数だけを見るため、Veramo（did-jwt-vc）が
// 渡された `header.kid` を実際に JWS ヘッダへ反映するかは検査していなかった。アダプタの `kid` 付与や Veramo の
// バージョン更新で `kid` が外れても、Docker が要る Nightly の `interop:veramo:didkit` が `main` で動くまで気づけない。
// この回帰テストは Docker 無しで実行できる。
//
// 検査するのは標準仕様の範囲のみ: JWS ヘッダの `kid`（RFC 7515 §4.1.4）と、VCDM 1.1 §6.3.1 の JWT 表現
// （`iss` = 発行者 DID）。独自の検証ルールは足さない。
//
// 依存は `test/interop/adapters/veramo` の `npm ci` で入れる（Docker イメージと同じ package-lock.json）。
//   cd test/interop/adapters/veramo && npm ci --omit=dev --no-audit --no-fund
//   node --test test/interop/__tests__/adapter-issue-jwt.veramo.test.mjs

import assert from 'node:assert/strict';
import test from 'node:test';
import { createVeramoAgent } from '../adapters/veramo/agent.mjs';
import { issueJwtVc } from '../adapters/veramo/issue-jwt.mjs';

function decodeJwtPart(jwt, index) {
  return JSON.parse(Buffer.from(jwt.split('.')[index], 'base64url').toString('utf8'));
}

test('実 Veramo adapter: 発行した JWT-VC の JWS ヘッダ kid が発行者 DID Document の検証メソッド id と一致する', async () => {
  const agent = createVeramoAgent();
  const identifier = await agent.didManagerCreate({
    provider: 'did:key',
    options: { keyType: 'Ed25519' },
  });

  const jwt = await issueJwtVc(agent, identifier, { name: 'x' });

  const header = decodeJwtPart(jwt, 0);
  const payload = decodeJwtPart(jwt, 1);
  assert.equal(header.alg, 'EdDSA');
  assert.equal(payload.iss, identifier.did, 'iss が発行者 DID と一致しない');

  // 期待値は発行者 DID の DID Document（署名鍵 = 唯一の検証メソッド）から取る。アダプタの組み立て式を
  // 再実装して比べるのではなく、DID を解決して得た id と照合する。
  const { didDocument } = await agent.resolveDid({ didUrl: identifier.did });
  const verificationMethodIds = didDocument.verificationMethod.map((method) => method.id);
  assert.equal(verificationMethodIds.length, 1, 'did:key の検証メソッドは署名鍵 1 つのはず');
  assert.equal(typeof header.kid, 'string', 'JWS ヘッダに kid が無い');
  assert.equal(header.kid, verificationMethodIds[0]);
  assert.ok(
    header.kid.startsWith(`${identifier.did}#`),
    `kid の DID 部分が発行者 DID でない: ${header.kid}`,
  );
});
