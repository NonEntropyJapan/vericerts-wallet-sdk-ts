/**
 * WUA `cnf.jwk` と別の公開鍵 JWK の同一性判定（`proof.ts` / `wua.ts` 共通）。
 *
 * WUA-PoP の署名鍵バインド検査（`proof.ts`）と WSCD バインド検査（`wua.ts`）は、
 * 「同じ WSCD 鍵か」を判定する同一のロジックを必要とする。失敗時のエラーコードだけが
 * 異なる（それぞれ `10201` 系 / `10102`）ため、判定そのものを本モジュールへ集約する。
 *
 * 鍵種別ごとの差異:
 * - `kty` / `crv` / `x` は鍵種別によらず string の完全一致を要求する。
 * - `y` は EC 鍵のみが持つ（OKP / Ed25519 は持たない。RFC 8037）。したがって `kty === 'EC'` の
 *   ときだけ `y` の string 一致を要求し、それ以外では双方に `y` が存在しないことを要求する
 *   （片側にだけ `y` があれば EC 鍵の偽装とみなして不一致）。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';

/** 鍵種別によらず一致を要求する JWK フィールド。 */
const JWK_MATCH_FIELDS = ['kty', 'crv', 'x'] as const;

/**
 * 2 つの公開鍵 JWK が同一の鍵を表すか判定する。
 *
 * `y` を無条件に要求すると OKP / Ed25519 では同一鍵同士でも常に不一致になるため、
 * `kty` に応じて `y` の要否を切り替える。
 *
 * @param cnfJwk WUA `cnf.jwk`（判定の基準となる側。`kty` を見て EC / OKP を分岐する）。
 * @param otherJwk 比較対象の公開鍵 JWK（signer 公開鍵 / WSCD 公開鍵）。
 * @returns 同一の鍵を表すなら `true`。
 */
export function publicKeyJwkMatches(
  cnfJwk: Record<string, unknown>,
  otherJwk: Record<string, unknown>,
): boolean {
  // JWK メンバはプロトタイプ鎖を辿らず own 限定で読む。鎖読みだと `cnf.jwk` が `{}` の
  // ような空オブジェクトで届いた場合に `Object.prototype` の `kty` / `crv` / `x` / `y` 汚染だけで
  // **両辺が同じ継承値を拾い**、一致判定が成立して cnf バインド検査が素通りする（fail-open）。
  // 呼び出し元が `cnf.jwk` を own 読みしても、`cnf.jwk` が own に存在する限りこの経路は塞げない。
  // JWK メンバは JSON 由来の純データ（文字列）なので `ownProperty` を使う。
  // ループ内で読んだ `kty` を保持して分岐に使う。読み直すと own のアクセサで 2 回の読みが別値に
  // なり得て、一致を検査した `kty` と `y` の要否を決める `kty` がずれる。
  let cnfKty: unknown;
  for (const field of JWK_MATCH_FIELDS) {
    const cnfValue = ownProperty<unknown>(cnfJwk, field);
    if (typeof cnfValue !== 'string' || cnfValue !== ownProperty<unknown>(otherJwk, field)) {
      return false;
    }
    if (field === 'kty') {
      cnfKty = cnfValue;
    }
  }
  const cnfY = ownProperty<unknown>(cnfJwk, 'y');
  const otherY = ownProperty<unknown>(otherJwk, 'y');
  if (cnfKty === 'EC') {
    return typeof cnfY === 'string' && cnfY === otherY;
  }
  // EC 以外（OKP）は双方 `y` を持たないことを要求する。
  return cnfY === undefined && otherY === undefined;
}
