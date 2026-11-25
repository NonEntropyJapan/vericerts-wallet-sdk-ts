import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

/**
 * IdP の JWKS と JwkRegistry の登録状態を照合し、owner が実行する操作を計画する。
 * 未登録の鍵には `registerKey`、JWKS から消えた鍵には 24 時間後を期限とする
 * `setNotAfter` を計画する。チェーンへのアクセスは `chain-client.mjs` が担う。
 *
 * ## 「新規 kid」の判定
 * IdP の JWKS に載っている modulus ごとに `modulusStatusForIss(issHash, limbs)` を読み、
 * `registered === false` なら未登録 = 新規として registerKey を計画する。ローカル状態を
 * 一切持たず、常にチェーン上の実際の登録状況を正とする（「ローカル状態がチェーンと
 * ドリフトする」クラスの不整合を構造的に避ける）。
 *
 * ## 「消失 kid」の判定
 * `JwkRegistry` には登録済み鍵の列挙 API がない。発行者ごとの登録履歴は、
 * `KeyRegistered` イベントを `issHash` で絞り込んで取得する。
 * 過去に登録された kid のうち、今回の JWKS に同じ kidHash が無ければ「消失」とみなし、
 * チェーン上の現在状態（`keyOf`）が「登録済み・未 revoke・grace 未設定（`notAfter === 0n`）」の
 * ときだけ `setNotAfter` を計画する。これにより:
 *   - 既に grace 済みの鍵へ setNotAfter を再発行しない（unregisterKey/revokeKey 済みも同様）。
 *   - `unregisterKey`（登録ミスの訂正）後に同じ kid が正しく再登録されても、古いイベントは
 *     `keyOf` が `registered === false` を返すため誤検知しない。
 *
 * ## 異常な JWKS への fail-closed
 * `alg` 欠落・`keys` 空配列・CDN の部分レスポンスなどで選別後の鍵が 0 件になると、登録済み鍵の
 * 全件が「消失」に見えて全鍵に `setNotAfter` を計画してしまう。IdP が実際に全鍵を一斉に撤去する
 * ことは無い（常に新 kid が載る）ため、0 件は「取得失敗」として `planActionsForIdp` が例外を
 * 投げ、何も計画・実行しない。
 *
 * ## 「復帰 kid」の判定
 * 過去に grace（`notAfter !== 0n`）を設定された kid が JWKS に戻ってきた場合（一時的な異常応答で
 * 誤って期限を切られた鍵など）は、同じ modulus であることを `modulusStatusForIss` で確かめたうえで
 * `setNotAfter(keyId, 0)` を計画して無期限に戻す。
 */

const MODULUS_LIMB_COUNT = 17;
const MODULUS_LIMB_BITS = 121n;
const MODULUS_LIMB_MASK = (1n << MODULUS_LIMB_BITS) - 1n;

/** JWKS から消えた登録済み鍵に設定する猶予期間（24 時間、単位は秒）。 */
export const GRACE_PERIOD_SECONDS = 24n * 60n * 60n;

/** 監視対象の発行者と、その署名鍵を取得する JWKS エンドポイント。 */
export const IDENTITY_PROVIDERS = Object.freeze([
  Object.freeze({
    iss: 'https://accounts.google.com',
    jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
  }),
  Object.freeze({
    iss: 'https://appleid.apple.com',
    jwksUri: 'https://appleid.apple.com/auth/keys',
  }),
]);

/**
 * RSA modulus（base64url エンコードされた `n`）を、SSO 回路と `JwkRegistry` が使う
 * 121 ビット幅の 17 個の limb に分割し、下位の limb から順に並べる。
 *
 * @param {string} base64urlModulus JWK の `n`（base64url、パディング任意）。
 * @returns {bigint[]} 長さ 17 の limb 配列（各要素は最大 121 ビット）。
 * @throws {Error} modulus が 0 / 空、または 17 × 121 = 2057bit を超えるとき。以前は上位 bit を
 *   黙って切り詰めて別鍵の modulus を `registerKey` の対象に計画していた（4096bit 鍵など）。
 */
export function modulusToLimbs(base64urlModulus) {
  const hex = Buffer.from(base64urlModulus, 'base64url').toString('hex');
  const modulusInt = hex === '' ? 0n : BigInt(`0x${hex}`);
  if (modulusInt === 0n) {
    throw new Error('RSA modulus が 0 または空（不正な JWK `n`）');
  }
  if (modulusInt >> (MODULUS_LIMB_BITS * BigInt(MODULUS_LIMB_COUNT)) !== 0n) {
    throw new Error(
      `RSA modulus が ${MODULUS_LIMB_COUNT} × ${MODULUS_LIMB_BITS}bit = ${MODULUS_LIMB_BITS * BigInt(MODULUS_LIMB_COUNT)}bit を超えている（${modulusInt.toString(2).length}bit。SSO 回路は RSA-2048 前提）。切り詰めて登録しないよう中止する`,
    );
  }
  return Array.from(
    { length: MODULUS_LIMB_COUNT },
    (_, i) => (modulusInt >> (MODULUS_LIMB_BITS * BigInt(i))) & MODULUS_LIMB_MASK,
  );
}

/**
 * JWKS ドキュメントから、SSO 回路が受理する RSA 署名鍵（`kty == "RSA" && alg == "RS256"`）だけを
 * 選ぶ。`kid` を欠くエントリは `(iss, kid)` で鍵を同定できないため除外する。
 *
 * @param {{ keys?: Array<Record<string, unknown>> }} jwks IdP の JWKS レスポンス（`{ keys: [...] }`）。
 * @returns {Array<{ kid: string, n: string }>}
 */
export function selectRsaSigningKeys(jwks) {
  const keys = Array.isArray(jwks?.keys) ? jwks.keys : [];
  return keys
    .filter(
      (key) =>
        key?.kty === 'RSA' &&
        key?.alg === 'RS256' &&
        typeof key?.kid === 'string' &&
        typeof key?.n === 'string',
    )
    .map((key) => ({ kid: key.kid, n: key.n }));
}

/**
 * `keccak256(bytes(iss))`（`0x` + 64 hex）。`JwkRegistry.registerKey` / `modulusStatusForIss` の
 * `issHash` 引数、`ZKValidator.onInstall` が束縛する値と同一。
 * @param {string} iss
 * @returns {string}
 */
export function computeIssHash(iss) {
  return `0x${bytesToHex(keccak_256(utf8ToBytes(iss)))}`;
}

/**
 * `keccak256(bytes(kid))`（`0x` + 64 hex）。`JwkRegistry.registerKey` の `kidHash` 引数と同一。
 * @param {string} kid
 * @returns {string}
 */
export function computeKidHash(kid) {
  return `0x${bytesToHex(keccak_256(utf8ToBytes(kid)))}`;
}

/**
 * `keyOf` が返す `JwkKey` 相当の最小形。`chainClient.getKey` が返す形と一致させる。
 * @typedef {{ notAfter: bigint, revoked: boolean, registered: boolean }} OnchainKeyState
 */

/**
 * `chainClient.getRegisteredEvents` が返す `KeyRegistered` イベント 1 件分の最小形。
 * @typedef {{ keyId: string, kidHash: string }} RegisteredEvent
 */

/** modulus が limb 表現に収まらない鍵を IdP/kid 付きのエラーにする。 */
function limbsOrThrow(idp, key) {
  try {
    return modulusToLimbs(key.n);
  } catch (error) {
    // 非対応サイズの鍵 1 件でも黙ってスキップせず IdP 単位で失敗させる。
    throw new Error(
      `jwk-registry-monitor: ${idp.iss} の kid=${key.kid} の modulus を limb 化できない: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
}

/**
 * 1 IdP 分の JWKS を、チェーン上の `JwkRegistry` の現在状態と突き合わせ、必要な owner 操作を計画する。
 * チェーン読み取りは注入された `chainClient`（`chain-client.mjs` の実装か、テスト用の
 * スタブ）を介して行うため、本関数自体はネットワークに触れず決定論的にテストできる。
 *
 * @param {object} params
 * @param {{ iss: string }} params.idp 対象 IdP（`IDENTITY_PROVIDERS` の 1 要素）。
 * @param {Array<{ kid: string, n: string }>} params.jwksKeys `selectRsaSigningKeys` 済みの JWKS エントリ。
 * @param {{
 *   getModulusStatus: (issHash: string, limbs: bigint[]) => Promise<{ registered: boolean }>,
 *   getRegisteredEvents: (issHash: string) => Promise<RegisteredEvent[]>,
 *   getKey: (keyId: string) => Promise<OnchainKeyState>,
 * }} params.chainClient
 * @param {bigint} params.now 現在時刻（UNIX 秒）。`setNotAfter` の grace 計算に使う。
 * @returns {Promise<{
 *   toRegister: Array<{ iss: string, kid: string, issHash: string, kidHash: string, limbs: bigint[] }>,
 *   toSetNotAfter: Array<{ iss: string, keyId: string, notAfter: bigint }>,
 *   toRestore: Array<{ iss: string, keyId: string, kid: string, notAfter: bigint }>,
 * }>}
 * @throws {Error} `jwksKeys` が空（異常な JWKS = 取得失敗）のとき。全鍵失効を計画しない fail-closed。
 *   modulus が 2057bit 超 / 0 の鍵が 1 件でもあるときも IdP 単位で中止する。
 */
export async function planActionsForIdp({ idp, jwksKeys, chainClient, now }) {
  if (jwksKeys.length === 0) {
    throw new Error(
      `jwk-registry-monitor: ${idp.iss} の JWKS から RSA/RS256 署名鍵を 1 件も選別できなかった（空・alg 欠落などの異常応答）。登録済み全鍵の失効を計画しないため中止する`,
    );
  }
  const issHash = computeIssHash(idp.iss);

  const liveEntries = jwksKeys.map((key) => ({
    kid: key.kid,
    kidHash: computeKidHash(key.kid),
    limbs: limbsOrThrow(idp, key),
  }));
  const liveKidHashes = new Set(liveEntries.map((entry) => entry.kidHash));

  const toRegister = [];
  const registeredLive = new Map(); // kidHash -> { kid, notAfter }（チェーンに登録済みの JWKS 掲載鍵）
  for (const entry of liveEntries) {
    const status = await chainClient.getModulusStatus(issHash, entry.limbs);
    if (status.registered) {
      registeredLive.set(entry.kidHash, { kid: entry.kid, notAfter: status.notAfter });
    } else {
      toRegister.push({
        iss: idp.iss,
        kid: entry.kid,
        issHash,
        kidHash: entry.kidHash,
        limbs: entry.limbs,
      });
    }
  }

  const toSetNotAfter = [];
  const toRestore = [];
  const historicalEvents = await chainClient.getRegisteredEvents(issHash);
  const consideredKeyIds = new Set();
  for (const event of historicalEvents) {
    if (consideredKeyIds.has(event.keyId)) continue;
    consideredKeyIds.add(event.keyId);
    if (liveKidHashes.has(event.kidHash)) {
      // まだ JWKS に存在する。過去に grace を設定された同一 modulus の鍵なら無期限に戻す。
      const live = registeredLive.get(event.kidHash);
      if (live === undefined) continue;
      const liveKey = await chainClient.getKey(event.keyId);
      if (!liveKey.registered || liveKey.revoked || liveKey.notAfter === 0n) continue;
      if (liveKey.notAfter !== live.notAfter) continue; // modulus が別の鍵（同一 kid の入れ替わり）
      toRestore.push({ iss: idp.iss, keyId: event.keyId, kid: live.kid, notAfter: 0n });
      continue;
    }

    const key = await chainClient.getKey(event.keyId);
    if (!key.registered || key.revoked) continue; // 訂正 (unregisterKey) 済み・revoke 済み
    if (key.notAfter !== 0n) continue; // 既に grace 設定済み（再発行しない）

    toSetNotAfter.push({ iss: idp.iss, keyId: event.keyId, notAfter: now + GRACE_PERIOD_SECONDS });
  }

  return { toRegister, toSetNotAfter, toRestore };
}
