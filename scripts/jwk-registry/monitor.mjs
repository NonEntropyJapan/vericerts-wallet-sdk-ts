/**
 * IdP の JWKS を監視し、`JwkRegistry` を更新する CLI。
 *
 * `monitor-core.mjs` が未登録鍵の登録、消えた鍵の期限設定、復帰した鍵の期限解除を計画する。
 * owner の署名鍵を設定した環境では、`chain-client.mjs` を通じて操作を実行する。
 * owner が MultiSig の場合は署名鍵を設定せず、署名者がログに出た操作を実行する。
 * この場合、対応が必要なら exit 1 で通知する。
 *
 * ## 環境変数
 * - `JWK_REGISTRY_RPC_URL`    `JwkRegistry` が乗るチェーンの JSON-RPC エンドポイント。
 * - `JWK_REGISTRY_ADDRESS`    `JwkRegistry` のデプロイ先アドレス。
 *     上記 2 つは**両方設定するか両方未設定**にする。両方未設定かつ他の `JWK_REGISTRY_*` も未設定なら
 *     未デプロイとして exit(0) でスキップする。片方だけ、または署名者 / 走査開始ブロックだけの設定は
 *     secret の投入漏れ・名前誤りなので明示エラー（exit 1）にする。
 * - `JWK_REGISTRY_SIGNER_KEY` （任意）owner の秘密鍵。設定時のみ registerKey / setNotAfter を実行する。
 *     未設定で registerKey / setNotAfter が必要と判定された場合は、実行すべき呼び出し内容をログしたうえで
 *     exit 1 にする（MultiSig 署名者が cron の失敗通知で気付くため）。
 * - `JWK_REGISTRY_FROM_BLOCK` （任意、既定 `0`）`KeyRegistered` ログの走査開始ブロック。
 *     未設定・空文字・空白のみは `0`（GitHub Actions は未設定 secret を空文字で渡す）。
 *     10 進の非負整数以外は明示エラーで失敗する。
 *
 * 各環境変数は前後の空白を除去し、空になったものは未設定として扱う。
 *
 * IdP の JWKS が空・異常（RSA/RS256 署名鍵を 1 件も選別できない）の場合はその IdP を取得失敗として
 * 扱い、全鍵失効を計画・実行せず exit 1 にする。他の IdP の処理は続行する。
 */

import { pathToFileURL } from 'node:url';
import { createChainClient as createRealChainClient } from './chain-client.mjs';
import {
  computeIssHash,
  computeKidHash,
  GRACE_PERIOD_SECONDS,
  IDENTITY_PROVIDERS,
  planActionsForIdp,
  selectRsaSigningKeys,
} from './monitor-core.mjs';

/** JWKS 取得 1 回あたりの待ち時間上限（ミリ秒）。 */
const FETCH_TIMEOUT_MS = 30_000;

/** @param {string} url @returns {Promise<{ keys?: Array<Record<string, unknown>> }>} */
async function fetchJwks(url) {
  // IdP がスローレスポンスで止まっても cron run が詰まらないよう打ち切る。
  const response = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!response.ok) {
    throw new Error(`jwk-registry-monitor: JWKS 取得に失敗 (${url}): HTTP ${response.status}`);
  }
  return response.json();
}

/** GitHub Actions の未設定 secret は空文字で渡る。空白のみも含めて未設定（`undefined`）に正規化する。 */
function readEnv(env, name) {
  return env[name]?.trim() || undefined;
}

/**
 * 1 IdP 分を処理し、計画された owner 操作の数を返す（署名者があれば実行済み、無ければ DRY RUN のみ）。
 * @returns {Promise<number>}
 */
async function reconcileIdp({ idp, jwks, chainClient, now }) {
  const jwksKeys = selectRsaSigningKeys(jwks);
  const { toRegister, toSetNotAfter, toRestore } = await planActionsForIdp({
    idp,
    jwksKeys,
    chainClient,
    now,
  });
  const pendingCount = toRegister.length + toSetNotAfter.length + toRestore.length;

  for (const action of toRegister) {
    console.log(`jwk-registry-monitor: 新規 kid を検出 iss=${action.iss} kid=${action.kid}`);
    if (chainClient.canExecute) {
      const txHash = await chainClient.registerKey(
        action.issHash,
        action.kidHash,
        action.limbs,
        0n,
      );
      console.log(`  -> registerKey を実行しました (tx: ${txHash})`);
    } else {
      console.log(
        `  -> DRY RUN（署名者未設定）: owner が registerKey(issHash=${action.issHash}, kidHash=${action.kidHash}, notAfter=0) を実行してください`,
      );
    }
  }

  for (const action of toSetNotAfter) {
    console.log(`jwk-registry-monitor: kid の消失を検出 iss=${action.iss} keyId=${action.keyId}`);
    if (chainClient.canExecute) {
      const txHash = await chainClient.setNotAfter(action.keyId, action.notAfter);
      console.log(`  -> setNotAfter を実行しました (tx: ${txHash}, notAfter: ${action.notAfter})`);
    } else {
      console.log(
        `  -> DRY RUN（署名者未設定）: owner が setNotAfter(keyId=${action.keyId}, notAfter=${action.notAfter}) を実行してください（grace ${GRACE_PERIOD_SECONDS}秒）`,
      );
    }
  }

  for (const action of toRestore) {
    console.log(
      `jwk-registry-monitor: grace 設定済みの kid が JWKS に復帰 iss=${action.iss} kid=${action.kid} keyId=${action.keyId}`,
    );
    if (chainClient.canExecute) {
      const txHash = await chainClient.setNotAfter(action.keyId, action.notAfter);
      console.log(`  -> setNotAfter(0) で無期限に戻しました (tx: ${txHash})`);
    } else {
      console.log(
        `  -> DRY RUN（署名者未設定）: owner が setNotAfter(keyId=${action.keyId}, notAfter=0) を実行してください`,
      );
    }
  }

  return pendingCount;
}

/**
 * @param {object} [deps] テスト用の注入点（CLI 実行時は既定値）。
 * @throws {Error} 設定不備・IdP の取得/異常応答・署名者未設定で要操作のとき（CLI は exit 1）。
 */
export async function main({
  env = process.env,
  fetchJwksImpl = fetchJwks,
  createChainClient = createRealChainClient,
} = {}) {
  const rpcUrl = readEnv(env, 'JWK_REGISTRY_RPC_URL');
  const registryAddress = readEnv(env, 'JWK_REGISTRY_ADDRESS');
  const signerPrivateKey = readEnv(env, 'JWK_REGISTRY_SIGNER_KEY');
  const fromBlock = readEnv(env, 'JWK_REGISTRY_FROM_BLOCK');

  if (!rpcUrl || !registryAddress) {
    const configured = [
      ['JWK_REGISTRY_RPC_URL', rpcUrl],
      ['JWK_REGISTRY_ADDRESS', registryAddress],
      ['JWK_REGISTRY_SIGNER_KEY', signerPrivateKey],
      ['JWK_REGISTRY_FROM_BLOCK', fromBlock],
    ]
      .filter(([, value]) => value !== undefined)
      .map(([name]) => name);
    if (configured.length > 0) {
      throw new Error(
        `jwk-registry-monitor: JWK_REGISTRY_RPC_URL と JWK_REGISTRY_ADDRESS は両方設定する必要がある（設定済み: ${configured.join(', ')}）。secret の投入漏れ・名前誤りの可能性がある`,
      );
    }
    console.log(
      'jwk-registry-monitor: JWK_REGISTRY_* が未設定のためスキップします（JwkRegistry 未デプロイ）。',
    );
    return;
  }

  const chainClient = createChainClient({
    rpcUrl,
    registryAddress,
    signerPrivateKey,
    fromBlock,
  });

  const now = BigInt(Math.floor(Date.now() / 1000));
  let pendingCount = 0;
  const failures = [];

  try {
    for (const idp of IDENTITY_PROVIDERS) {
      try {
        const jwks = await fetchJwksImpl(idp.jwksUri);
        pendingCount += await reconcileIdp({ idp, jwks, chainClient, now });
      } catch (error) {
        // 1 IdP の異常応答・障害で他 IdP の鍵検知を止めない。最後にまとめて失敗させる。
        console.error(error);
        failures.push(`${idp.iss}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    if (pendingCount > 0 && !chainClient.canExecute) {
      failures.push(
        `署名者（JWK_REGISTRY_SIGNER_KEY）が未設定のため owner 操作 ${pendingCount} 件が未実行（上記 DRY RUN の呼び出しを owner が実行すること）`,
      );
    }
    if (failures.length > 0) {
      throw new Error(`jwk-registry-monitor: 対応が必要です\n- ${failures.join('\n- ')}`);
    }
    if (pendingCount === 0) {
      console.log(
        'jwk-registry-monitor: 全 IdP の JWKS が JwkRegistry の登録状況と一致しています（対応不要）。',
      );
    }
  } finally {
    await chainClient.destroy();
  }
}

// `computeIssHash` / `computeKidHash` は `main()` からは直接使わないが、CLI 単体で
// issHash/kidHash を確認したい運用者向けに再エクスポートする（`node -e` からの手動確認用）。
export { computeIssHash, computeKidHash };

// CLI として実行されたときだけ走らせる（テストから `main` を import できるようにする）。
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
