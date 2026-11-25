// test/interop/adapters/veramo/server.mjs
//
// Veramo（実ライブラリ・npm 公式パッケージ、モックなし）を相互運用テスト harness の統一ピア契約
// （`GET /health`・`GET /did`・`POST /vc/issue`・`POST /vc/verify`）で公開する薄いアダプタ。
// `did:key` + JWT-VC（`@veramo/credential-jwt`）で発行・検証する。DID 解決は Veramo 自身の
// `key-did-resolver` に任せるため、`/vc/verify` は生 JWT を渡すだけで完結する（外部鍵の受け渡し不要）。
//
// これに加えて DID 解決マトリクス用に `GET /identifiers/{did}` を公開する。
// 経路・応答形式は DIF DID Resolution HTTPS Binding に合わせてあり、外部イメージの
// didkit-http の同名エンドポイントと同じクライアント（`test/interop/lib/did-resolution-clients.mjs`）で
// 叩ける。解決そのものは Veramo の `resolveDid` に委譲する（当方で DID Document を組み立てない —
// それでは「Veramo が解決できるか」を検証したことにならない）。

import { createServer } from 'node:http';
import { createVeramoAgent } from './agent.mjs';
import { issueJwtVc } from './issue-jwt.mjs';

const agent = createVeramoAgent();

// 起動のたびに新規 did:key を発行する（このプロセスの寿命の間は固定）。
const identifier = await agent.didManagerCreate({
  provider: 'did:key',
  options: { keyType: 'Ed25519' },
});
const PORT = Number(process.env.PORT ?? 8091);

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
    });
    req.on('end', () => {
      try {
        resolve(data.length > 0 ? JSON.parse(data) : {});
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(payload);
}

const IDENTIFIERS_PREFIX = '/identifiers/';

/**
 * DIF DID Resolution HTTPS Binding の `GET /identifiers/{did}`。
 *
 * 応答は Veramo の `resolveDid` が返す Resolution Result（`didResolutionMetadata` /
 * `didDocument` / `didDocumentMetadata`）をそのまま返す。解決できなかった場合は 404 にして、
 * 呼び出し側（`run-did-resolution-matrix.mjs`）が 2xx を「解決できた」と誤認しないようにする
 * — `didResolutionMetadata.error` を 200 で返すと、fail-closed 検査を 1 段しか通らない。
 */
async function handleResolve(res, pathname) {
  const didUrl = decodeURIComponent(pathname.slice(IDENTIFIERS_PREFIX.length));
  if (didUrl === '') {
    return sendJson(res, 400, { didResolutionMetadata: { error: 'invalidDid' } });
  }
  const result = await agent.resolveDid({ didUrl });
  const error = result?.didResolutionMetadata?.error;
  return sendJson(res, error === undefined || error === null ? 200 : 404, result);
}

const server = createServer(async (req, res) => {
  try {
    // クエリ（DIF Binding の解決オプション）を落としてパスだけで分岐する。
    const { pathname } = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && pathname.startsWith(IDENTIFIERS_PREFIX)) {
      return await handleResolve(res, pathname);
    }
    if (req.method === 'GET' && req.url === '/health') {
      return sendJson(res, 200, { status: 'ok', peer: 'veramo' });
    }
    if (req.method === 'GET' && req.url === '/did') {
      return sendJson(res, 200, { did: identifier.did, formats: ['jwt_vc'] });
    }
    if (req.method === 'POST' && req.url === '/vc/issue') {
      const body = await readJsonBody(req);
      const subject = body?.subject ?? {};
      const jwt = await issueJwtVc(agent, identifier, subject);
      return sendJson(res, 200, { jwt, format: 'jwt_vc', issuer: identifier.did });
    }
    if (req.method === 'POST' && req.url === '/vc/verify') {
      const body = await readJsonBody(req);
      if (typeof body?.jwt !== 'string') {
        return sendJson(res, 400, { verified: false, error: 'jwt is required (string)' });
      }
      const result = await agent.verifyCredential({ credential: body.jwt });
      return sendJson(res, 200, {
        verified: result.verified === true,
        error: result.error?.message,
      });
    }
    return sendJson(res, 404, { error: 'not found' });
  } catch (error) {
    return sendJson(res, 500, { error: String(error) });
  }
});

server.listen(PORT, () => {
  console.log(`[veramo-peer] listening on :${PORT} (issuer ${identifier.did})`);
});
