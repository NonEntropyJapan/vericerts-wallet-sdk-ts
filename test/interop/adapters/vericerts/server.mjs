// test/interop/adapters/vericerts/server.mjs
//
// VeriCerts Wallet SDK を相互運用テスト harness の統一ピア契約
// （`GET /health`・`GET /did`・`POST /vc/issue`・`POST /vc/verify`）で公開する薄いアダプタ。
// SDK のパッケージ公開 entry から発行・検証機能を使う。
//
// 発行鍵は test/interop/fixtures/vericerts-issuer.json 固定（相互運用テスト専用、本番鍵ではない）。

import { readFileSync } from 'node:fs';
import { VericertsError } from '@vericerts/vericerts-wallet-sdk/common';
import {
  didDocumentToVerifierKey,
  verifyCredential,
} from '@vericerts/vericerts-wallet-sdk/credential';
import { resolveDidKey } from '@vericerts/vericerts-wallet-sdk/identity';
import { createIssuerSigner, issueJwtVc } from './issue-jwt.mjs';

const FIXTURE = JSON.parse(
  readFileSync(new URL('../../fixtures/vericerts-issuer.json', import.meta.url), 'utf8'),
);
const SIGNER = createIssuerSigner(FIXTURE);
const PORT = Number(process.env.PORT ?? 8090);

/**
 * `did:key:z...`（Ed25519、multicodec `0xed01`）から `publicKeyJwk` を導出する。
 * このアダプタが相互接続するピアはすべて Ed25519 did:key を発行者 DID に使うため、
 * 他方式（secp256k1 / P-256）は対象外（未対応 DID は 2001 として扱う）。
 *
 * @param did 解決対象の DID 文字列。
 * @returns 導出した公開鍵 JWK。
 * @throws DID が `did:key:` 形式でない・Ed25519 でない場合。
 */
function resolveDidKeyEd25519Jwk(did) {
  if (!did.startsWith('did:key:')) {
    throw new Error(`unsupported issuer DID method (expected did:key): ${did}`);
  }
  const { publicKeyJwk } = didDocumentToVerifierKey(resolveDidKey(did));
  if (publicKeyJwk?.kty !== 'OKP' || publicKeyJwk.crv !== 'Ed25519') {
    throw new Error('unsupported did:key codec (expected Ed25519 0xed01)');
  }
  return publicKeyJwk;
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

async function handleIssue(req) {
  const body = await req.json();
  const subject = body?.subject ?? {};
  const now = new Date();
  const jwt = issueJwtVc(FIXTURE, SIGNER, subject, now);
  return json({ jwt, format: 'jwt_vc', issuer: FIXTURE.did });
}

export async function handleVerify(req) {
  const body = await req.json();
  const jwt = body?.jwt;
  if (typeof jwt !== 'string') {
    return json({ verified: false, error: 'jwt is required (string)' }, 400);
  }
  let publicKeyJwk = body?.publicKeyJwk;
  if (publicKeyJwk === undefined) {
    // 明示指定が無ければ、JWT の `iss`（did:key を想定）から自前で解決する。
    // ピア間で鍵材料を out-of-band に受け渡さなくても検証できることを確かめる
    // （相互運用テストの本質的な部分）。
    try {
      const [, payloadB64] = jwt.split('.');
      const payload = JSON.parse(Buffer.from(payloadB64 ?? '', 'base64url').toString('utf8'));
      publicKeyJwk = resolveDidKeyEd25519Jwk(payload.iss);
    } catch (error) {
      return json({ verified: false, error: `cannot resolve issuer did:key: ${String(error)}` });
    }
  }
  try {
    const result = verifyCredential(jwt, { key: { publicKeyJwk } });
    return json({ verified: true, issuer: result.payload.iss });
  } catch (error) {
    const message =
      error instanceof VericertsError ? `${error.code}: ${error.message}` : String(error);
    return json({ verified: false, error: message });
  }
}

if (import.meta.main) {
  Bun.serve({
    port: PORT,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === '/health') {
        return json({ status: 'ok', peer: 'vericerts' });
      }
      if (url.pathname === '/did' && req.method === 'GET') {
        return json({ did: FIXTURE.did, publicKeyJwk: FIXTURE.publicKeyJwk, formats: ['jwt_vc'] });
      }
      if (url.pathname === '/vc/issue' && req.method === 'POST') {
        return handleIssue(req);
      }
      if (url.pathname === '/vc/verify' && req.method === 'POST') {
        return handleVerify(req);
      }
      return json({ error: 'not found' }, 404);
    },
  });
  console.log(`[vericerts-peer] listening on :${PORT} (issuer ${FIXTURE.did})`);
}
