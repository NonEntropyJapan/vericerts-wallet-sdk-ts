/**
 * チェーン構築で候補 CA に課す制約の判定（RFC 5280 §6.1.4）。
 *
 * 証明書 1 通ぶんの**主張**（`ca-constraints.ts` / `name-constraints.ts` が読み取った構造体）を、
 * 「この候補を中間 CA として使ってよいか」という**チェーン上の判断**に変換する述語を置く。
 * 拡張の DER を読むのは各読み取りモジュールの仕事で、本モジュールは値を解釈するだけである。
 * 唯一の呼び出し元はチェーン検証（`trust/etsi-tsl/chain.ts`）。
 *
 * **`ParsedCertificate` を引数に取らない。** `trust/x509/` が `etsi-tsl/x509.ts` を import すると
 * ディレクトリ間で循環参照になる。制約の構造体と、名前の照合に要る最小の構造的な型
 * （{@link CertificateNames}）だけを受け取る。`ParsedCertificate` は構造的にこれを満たす。
 *
 * セキュリティ上の注意:
 * - 例外を投げず真偽値で返す。戻り値に証明書本文 / DN / 鍵素材を含めない。
 * - 評価できない制約は拒否側に倒す（fail-closed）。
 */

import type { CaConstraints } from './ca-constraints.js';
import type { AltNames, NameConstraints } from './name-constraints.js';
import { namesSatisfyConstraints } from './name-matching.js';

/** 名前制約の照合に必要な、証明書 1 通ぶんの名前。 */
export interface CertificateNames {
  /** subject DN の DER バイト列。 */
  readonly subjectDer: Uint8Array;
  /** 照合対象の SubjectAltName。 */
  readonly altNames: AltNames;
}

/**
 * 証明書が他の証明書を発行してよい CA か（RFC 5280 §4.2.1.9 / §4.2.1.3）。
 *
 * **中間証明書に必ず課す。** subject DN の一致だけで中間を選ぶと、信頼済み QTSP が発行した
 * **エンドエンティティ証明書**（＝攻撃者が正当に持ち得る証明書）をそのまま中間 CA として使える。
 * 攻撃者は自分の秘密鍵で任意の leaf に署名し、その証明書を `intermediatesDer` に添えるだけで
 * DN の連結も各段の署名検証も成立するチェーンを組み立てられ、`wallet/issuer-trust/x5c.ts` の
 * Issuer 鍵解決（`x5c`）がそれを信頼の起点にしてしまう。CA 制約は「CA であること」を証明書自身に
 * 主張させる唯一の手段なので、ここを省くと発行連鎖の検証そのものが意味を失う。
 *
 * **Trust Anchor には課さない。** Anchor は TSL から取り出して設定した信頼の起点であり、RFC 5280
 * §6.1 も path validation の入力（trust anchor）自体には証明書拡張の検査を課さない。Anchor に
 * 何を置くかは呼び出し側の設定（`trustAnchorsDer`）の問題で、チェーン構築中に攻撃者が差し込める
 * `intermediatesDer` とは信頼の前提が違う。
 *
 * @param ca 中間 CA 候補の CA 制約。
 * @returns `cA:TRUE` かつ keyUsage が証明書への署名を許していれば `true`。
 */
export function canIssueCertificates(ca: CaConstraints): boolean {
  return ca.isCa && ca.canSignCertificates;
}

/**
 * `ca` の basicConstraints `pathLenConstraint` が、その下に `intermediatesBelow` 段の中間 CA を
 * 許すか（RFC 5280 §4.2.1.9 / §6.1.4 (m)）。
 *
 * **なぜ必要か。** `cA:TRUE` だけを見て `pathLenConstraint` を読まないと、QTSP が「この CA の下に
 * さらに CA を作らせない」と明示した制約が無視される。攻撃者は pathLen:0 の中間 CA の配下に自分の
 * sub-CA を挟んだチェーンを組めてしまい、`cA:TRUE` を要求した目的（発行範囲を証明書自身の主張に
 * 縛ること）が 1 段ぶん緩む。
 *
 * **self-issued の例外は要らない。** RFC 5280 §6.1.4 (m) は self-issued 証明書を段数に数えないが、
 * 呼び出し元は同一 subject の再利用をループ検出で既に拒否しており、self-issued な中間証明書は
 * そもそも辿れない。数え方が分岐しないので例外処理を置かない。**ただし帰結は「数えない」ではなく
 * 「使わない」である** — 鍵ロールオーバー用の正当な self-issued 証明書がバンドルに入っていても、
 * それを辿るチェーンはスキップではなく `trusted:false` になる。RFC の path validation とは
 * ここで挙動が分かれる。
 *
 * **Trust Anchor には課さない。**{@link canIssueCertificates} と同じ理由で、Anchor は呼び出し側の
 * 設定であって攻撃者が差し込めるものではない。
 *
 * @param ca 中間 CA 候補の CA 制約。
 * @param intermediatesBelow `ca` より下（leaf 側）にある中間 CA の段数。
 * @returns 制約が無い（`undefined`）か、段数が制約以内なら `true`。
 */
export function withinPathLength(ca: CaConstraints, intermediatesBelow: number): boolean {
  return ca.pathLenConstraint === undefined || ca.pathLenConstraint >= intermediatesBelow;
}

/**
 * 候補 CA の nameConstraints が、その配下の全証明書の名前を許すか（RFC 5280 §6.1.4 (g)）。
 *
 * **なぜ必要か。** 読まなければ、発行できる名前空間を限定して渡された中間 CA を手に入れた者が、
 * 範囲外の識別子（他社の `origin` や Issuer の `iss`）を名乗る leaf を発行できてしまう。
 * {@link canIssueCertificates} の「発行してよいか」に対し、ここは「何に対して発行してよいか」を見る。
 *
 * **評価できない制約は落とす（fail-closed）。** 未対応の GeneralName 種別・壊れた拡張は
 * `evaluable:false` になり、「制約なし」と読むと書き換えるだけで制約を消せてしまう。
 * **Trust Anchor には課さない**のは {@link canIssueCertificates} と同じ理由（RFC 5280 §6.1 も
 * path validation の入力には拡張検査を課さない。RFC 5937 のような anchor 制約は対象外）。
 *
 * @param constraints 中間 CA 候補の nameConstraints（拡張が無ければ `undefined`）。
 * @param below 候補より下（leaf 側）にある証明書すべて（leaf を含む）。
 * @returns 制約が無いか、配下すべてが制約を満たすなら `true`。
 */
export function allowsNamesBelow(
  constraints: NameConstraints | undefined,
  below: readonly CertificateNames[],
): boolean {
  if (constraints === undefined) {
    return true;
  }
  if (!constraints.evaluable) {
    return false;
  }
  return below.every((c) => namesSatisfyConstraints(c.subjectDer, c.altNames, constraints));
}
