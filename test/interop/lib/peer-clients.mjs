// test/interop/lib/peer-clients.mjs
//
// run-peer-matrix.mjs が実ピアへ発行・検証・生存確認を行う HTTP / サブプロセスのクライアント群。
// マトリクス本体（組み合わせの列挙と結果記録）を Linterly の 1 ファイル 300 行上限に収めるため
// 切り出した。

import { fileURLToPath } from 'node:url';
import { baseUrlOf } from './host-ports.mjs';

async function fetchJson(fetchImpl, url, options) {
  const res = await fetchImpl(url, options);
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { ok: res.ok, status: res.status, body };
}

/** uniform ピア（vericerts / veramo）に VC を 1 通発行させる。 */
export async function issueFromUniformPeer(fetchImpl, peer) {
  const { ok, body } = await fetchJson(fetchImpl, `${baseUrlOf(peer)}/vc/issue`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ subject: { name: 'interop-matrix-test' } }),
  });
  if (!ok || typeof body?.jwt !== 'string') {
    throw new Error(`issue failed: ${JSON.stringify(body)}`);
  }
  return body.jwt;
}

/**
 * uniform ピアに JWT-VC を検証させる。
 *
 * fail-closed: 非 2xx は HTTP ステータスを理由に残す。本文が JSON でない 502 等で
 * `body?.error` が取れないと、呼び出し側の既定文言「検証が verified=false を返した」に落ちて
 * プロキシ/アダプタのダウンが「検証器が評価して拒否した」と読めてしまう（`verifyWithNativePeer`
 * と同形にそろえる）。
 */
export async function verifyWithUniformPeer(fetchImpl, peer, jwt) {
  const { ok, status, body } = await fetchJson(fetchImpl, `${baseUrlOf(peer)}/vc/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jwt }),
  });
  if (!ok) {
    const excerpt = (typeof body === 'string' ? body : JSON.stringify(body)).slice(0, 200);
    return { verified: false, error: `HTTP ${status}: ${body?.error ?? excerpt}` };
  }
  return { verified: body?.verified === true, error: body?.error };
}

/**
 * native ピア（VC-API、didkit/sphereon）に VC（JWT-VC 文字列または LD-Proof オブジェクト）を
 * 検証させる。
 *
 * fail-closed: pass にするのは「2xx かつ JSON オブジェクトで、`errors` が空配列、
 * `checks` が 1 件以上」の応答だけ。5xx の HTML・404 の `{message}` 等を「errors が空」とみなして
 * pass にしない（クラッシュ/設定ミス/パス違いのピアで Nightly が緑になるのを防ぐ）。
 */
export async function verifyWithNativePeer(fetchImpl, peer, credential) {
  const { ok, status, body } = await fetchJson(fetchImpl, `${baseUrlOf(peer)}/credentials/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ verifiableCredential: credential, options: {} }),
  });
  const errors = Array.isArray(body) ? body : body?.errors;
  const errorText = Array.isArray(errors) && errors.length > 0 ? errors.join('; ') : undefined;
  const excerpt = (typeof body === 'string' ? body : JSON.stringify(body)).slice(0, 200);
  if (!ok) return { verified: false, error: `HTTP ${status}: ${errorText ?? excerpt}` };
  if (body === null || typeof body !== 'object') {
    return { verified: false, error: `JSON 以外の応答を返した: ${excerpt}` };
  }
  if (errorText) return { verified: false, error: errorText };
  if (!Array.isArray(errors)) {
    return { verified: false, error: `応答に errors 配列が無い: ${excerpt}` };
  }
  if (!Array.isArray(body.checks) || body.checks.length === 0) {
    return { verified: false, error: `応答に checks が無く検証が実施されたか不明: ${excerpt}` };
  }
  return { verified: true, error: undefined };
}

/** native ピア（VC-API、didkit/sphereon）に LD-Proof VC を 1 通発行させる。 */
export async function issueFromNativePeer(fetchImpl, peer, did) {
  const now = new Date().toISOString();
  const { ok, body } = await fetchJson(fetchImpl, `${baseUrlOf(peer)}/credentials/issue`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      credential: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        issuer: did,
        issuanceDate: now,
        credentialSubject: { id: did },
      },
      options: {},
    }),
  });
  if (!ok || body?.verifiableCredential === undefined) {
    throw new Error(`issue failed: ${JSON.stringify(body)}`);
  }
  return body.verifiableCredential;
}

export async function checkPeerAlive(fetchImpl, baseUrl, healthPath = '/health') {
  try {
    const res = await fetchImpl(`${baseUrl}${healthPath}`, {
      redirect: 'error',
      signal: AbortSignal.timeout(3000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

const COMPOSE_FILE = fileURLToPath(new URL('../docker-compose.yml', import.meta.url));
const WALTID_PROTOCOL_TIMEOUT_MS = 5 * 60 * 1000;
const WALTID_RESULT_STATUSES = new Set(['pass', 'fail', 'skipped']);

/**
 * walt.id issuer-api/verifier-api の OID4VCI/OID4VP プロトコル層（Offer→Receive→Present）を
 * `run-waltid-protocol.mjs` へサブプロセスとして委譲する。当該スクリプトは
 * ドライバは SDK の公開 API と Bun の TLS オプションを使う。
 *
 * walt.id の `baseUrl` は SDK の公開ホスト検査（`isPublicHttpsUrl`）を通る FQDN
 * （`*.waltid.interop.example`）で、compose ネットワークの DNS（`waltid-tls-proxy` の network alias）で
 * しか解決できない。ホストの `/etc/hosts` は共有 self-hosted ランナーでは書き換えられないため、
 * ドライバは compose の `waltid-driver` サービス（one-off）としてネットワーク内で実行する。
 * プロジェクト名は `COMPOSE_PROJECT_NAME` を子へ引き継ぐ。
 * `peers.*.baseUrl` はそのコンテナから見た管理系 API の URL（`http://waltid-issuer:7002` 等）。
 *
 * @returns 子プロセスが出力した `PairResult[]`。起動失敗・出力が JSON として解釈できない場合は
 *          両ペアを fail として報告する（smoke 相当の生存確認も兼ねる）。
 */
export function runWaltidProtocol(spawnImpl, peers) {
  // 2 ペアに**同じ理由**を載せるので、verifier は issuer の巻き添えとして `causedBy` を付ける。
  // レポートを処理する側でも 2 件の失敗が同根だと判別できる。
  const failBoth = (reason) => [
    { pair: 'interop:waltid-issuer:vericerts', status: 'fail', reason },
    {
      pair: 'interop:vericerts:waltid-verifier',
      status: 'fail',
      reason,
      causedBy: 'interop:waltid-issuer:vericerts',
    },
  ];
  // timeout で SIGKILL されるのは `docker compose` CLI だけで、`--rm` の後始末は走らずコンテナが残る。
  // `docker compose down -v` は one-off コンテナを消さず（`--remove-orphans` が要る）、残った
  // コンテナが project の network 削除も妨げる。名前を付けておき、spawn 失敗時に自分で消す。
  const containerName = `${process.env.COMPOSE_PROJECT_NAME ?? 'vericerts-interop'}-waltid-driver-${process.pid}`;
  const proc = spawnImpl(
    'docker',
    [
      'compose',
      // `run` のビルド・進捗は既定で標準出力へ出る。ドライバの JSON 出力だけを標準出力に残す。
      '--progress',
      'quiet',
      '-f',
      COMPOSE_FILE,
      'run',
      '--rm',
      '--no-deps',
      '-T',
      '--name',
      containerName,
      '-e',
      `WALTID_ISSUER_ADMIN_BASE_URL=${peers.issuer.baseUrl}`,
      '-e',
      `WALTID_VERIFIER_ADMIN_BASE_URL=${peers.verifier.baseUrl}`,
      'waltid-driver',
    ],
    {
      encoding: 'utf8',
      // 子が応答待ちで停止しても matrix が無期限に待たないようにする。
      // 超過時は spawnSync が `proc.error`（ETIMEDOUT）を設定し、下の failBoth に倒れる。
      timeout: WALTID_PROTOCOL_TIMEOUT_MS,
      killSignal: 'SIGKILL',
    },
  );
  if (proc.error) {
    spawnImpl('docker', ['rm', '-f', containerName], { encoding: 'utf8', timeout: 30_000 });
    return failBoth(`run-waltid-protocol.mjs の起動に失敗した: ${proc.error.message}`);
  }
  if (typeof proc.stdout !== 'string' || proc.stdout.trim() === '') {
    return failBoth(
      `run-waltid-protocol.mjs が標準出力を返さなかった（stderr: ${proc.stderr ?? ''}）`,
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(proc.stdout);
  } catch (error) {
    return failBoth(
      `run-waltid-protocol.mjs の出力が JSON として解釈できなかった: ${error.message}`,
    );
  }
  // `results` 欠落・非配列・空・不正要素を素通しすると後段の `results.push(...x)` が TypeError で
  // matrix 全体を中断し、既存の全ペア結果が失われる。
  const valid =
    Array.isArray(parsed?.results) &&
    parsed.results.length > 0 &&
    parsed.results.every(
      (r) => typeof r?.pair === 'string' && WALTID_RESULT_STATUSES.has(r.status),
    );
  if (!valid) {
    return failBoth('run-waltid-protocol.mjs の出力が { results: PairResult[] } 形式ではなかった');
  }
  // 同梱構成は公開ホスト検査を通る FQDN で実駆動するので、全ペアが skipped なのは
  // `baseUrl` が公開ホスト検査を通らない名前へ退行した（公開ホスト検査で駆動前にスキップした）合図。
  // skipped のままだと Issue 自動起票の対象外で、Offer→Receive→Present が一度も走らないまま
  // Nightly が緑になる。fail に倒して Nightly と自動起票で検知する。
  if (parsed.results.every((r) => r.status === 'skipped')) {
    return failBoth(
      `walt.id の全ペアが skipped になった（実駆動されていない）: ${parsed.results.map((r) => r.reason).join(' / ')}`,
    );
  }
  return parsed.results;
}
