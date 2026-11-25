/**
 * Dashboard ログエントリ 1 件分の JWS 署名検証。
 *
 * エクスポート検証（`../dashboard-log/dashboard-log-import.ts`）と保存済みログの chain 検証（`./chain.ts`）の双方が
 * 使う。**同一実装を共有することが重要**で、片方だけが「署名だけ差し替えて本文を改ざんする」攻撃への
 * 防御を持つ状態を作らない。
 *
 * セキュリティ上の注意:
 * - 検証失敗の理由に元データ（payload / 署名バイト列）を載せない。真偽値だけを返す。
 */

import type { CredentialAlg } from '../../credential/index.js';
import { decodeCompactJws, verifyWithJwkOrFalse } from '../../credential/vc/jws.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { SEQ_PAD_WIDTH } from '../dashboard-log/dashboard-log-shared.js';
import type { DashboardLogEntry } from '../types.js';

/** 署名検証に用いる検証鍵（署名時のペルソナ / エフェメラル公開鍵）。 */
export interface DashboardLogVerifierKey {
  /** JWS 署名アルゴリズム（`ES256` = P-256 / `ES256K` = secp256k1）。 */
  readonly alg: CredentialAlg;
  /** 署名者の EC 公開鍵 JWK。 */
  readonly publicKeyJwk: PublicKeyJwk;
}

/**
 * JWS ヘッダの `kid` から署名時点の検証鍵を解決する関数。
 *
 * Dashboard ログは JWS ヘッダの `kid` で署名時点の鍵を選ぶ。
 * K3 Passkey-PRF 由来のログ専用鍵は WebAuthn PRF 出力が個々の
 * credential に結び付くため別 Passkey の登録・復旧で導出鍵が変わり得るうえ、PRF 非対応時の seed 由来
 * 代替鍵と、従来にアクティブペルソナ鍵（K2 由来・`ES256K`）で署名された旧エントリが**同一 chain 上
 * に混在**する。単一の {@link DashboardLogVerifierKey} で全件を検証すると、当時の鍵で正しく署名された
 * エントリまで `signatureInvalid` になり、Dashboard の改ざん警告が常時点灯して検知が意味を失う。
 *
 * そこで検証側は鍵そのものではなく「`kid` → 鍵」の解決関数を受け取る。`kid` は {@link extractKid} が
 * ヘッダから取り出す。従来の旧エントリは `kid` を持たないため（当時の signer に `kid` フィールドが
 * 無い）、`undefined` に対する解決先（旧ペルソナ鍵）も組込先が与える。
 *
 * **fail-closed**: 解決できない `kid` では `undefined` を返す。呼び出し側（`./chain.ts`）は検証を
 * 飛ばさず `keyUnresolved` として報告する。エントリに添付された公開鍵をその場で信頼して検証を通すことは
 * しない。検証契約は `kid` と公開鍵の対応表自体の完全性も求める。
 *
 * @param kid JWS ヘッダの `kid`。ヘッダに無い場合は `undefined`（従来の旧 K2 エントリ）。
 * @returns 署名時点の検証鍵。既知鍵集合に無ければ `undefined`。
 */
export type DashboardLogVerifierKeyResolver = (
  kid: string | undefined,
) => DashboardLogVerifierKey | undefined;

/**
 * エントリ ID（`seqToId` 形式）から連番を取り出す。
 *
 * `nextSeq` はキー群から最大値を採るだけなので連番として読めない ID を黙って無視できるが、chain 検証
 * （`./chain.ts`）は「連番として解釈できない ID」自体を破損として報告する必要がある。そのため解釈の
 * 成否を `undefined` で区別できる別関数として切り出す。
 *
 * @param id エントリ ID（末尾 `SEQ_PAD_WIDTH` 桁がゼロ埋め連番）。
 * @returns 連番。ゼロ埋め連番として解釈できなければ `undefined`。
 */
export function seqOf(id: string): number | undefined {
  const digits = id.slice(-SEQ_PAD_WIDTH);
  // `Number.parseInt` は先頭が数字なら末尾のゴミを黙って捨てるため、全桁が数字であることを先に確かめる。
  if (digits.length !== SEQ_PAD_WIDTH || !/^\d+$/.test(digits)) {
    return undefined;
  }
  return Number.parseInt(digits, 10);
}

/**
 * エントリの JWS ヘッダから `kid`（署名鍵の識別子）を取り出す。
 *
 * 多鍵検証（{@link DashboardLogVerifierKeyResolver}）の解決キーになる。`kid` は
 * 旧形式のエントリには `kid` が無い。その場合は `undefined` をリゾルバに渡して署名時の鍵を選ぶ。
 *
 * デコード不能なエントリ（storage 破損 / 改ざん）でも例外にせず `undefined` を返す。`./chain.ts` は
 * 1 件目の破損で打ち切らずレポートを返す契約であり、ここで投げると検証全体が落ちる。旧形式として
 * 解決された鍵での検証は {@link verifyEntrySignature} が `false`（`signatureInvalid`）に畳み込み、
 * 解決できなければ `keyUnresolved` になるため、どちらの経路でも `ok` は落ちる（fail-closed）。
 *
 * @param entry 検証対象のエントリ。
 * @returns ヘッダの `kid`。デコード不能・`kid` が文字列でない場合は `undefined`。
 */
export function extractKid(entry: DashboardLogEntry): string | undefined {
  try {
    const { header } = decodeCompactJws(entry.signature);
    return typeof header.kid === 'string' ? header.kid : undefined;
  } catch {
    return undefined;
  }
}

/**
 * エントリの JWS 署名を検証する。署名対象 payload が本文フィールドと一致し、かつ検証鍵で署名が有効なら
 * `true`。いずれかが不一致なら `false`（alg と検証鍵の kty / crv の不一致も `false` に畳み込む）。
 */
export function verifyEntrySignature(
  entry: DashboardLogEntry,
  verifierKey: DashboardLogVerifierKey,
): boolean {
  let decoded: ReturnType<typeof decodeCompactJws>;
  try {
    decoded = decodeCompactJws(entry.signature);
  } catch {
    return false;
  }
  // 署名対象 payload（append の signedPart）が本文フィールドと一致することを確認する
  // （signature だけ差し替えて本文を改ざんする攻撃を防ぐ）。
  const signed = decoded.payload;
  if (
    signed.type !== entry.type ||
    signed.recordedAt !== entry.recordedAt ||
    (signed.prevHash ?? null) !== entry.prevHash ||
    JSON.stringify(signed.payload) !== JSON.stringify(entry.payload)
  ) {
    return false;
  }
  return verifyWithJwkOrFalse(verifierKey.alg, decoded, verifierKey.publicKeyJwk);
}
