/**
 * 解釈できない critical 拡張の検出（RFC 5280 §6.1.4 (f)）。
 *
 * **なぜ必要か。** `critical` は CA が「この制限を解釈できないなら証明書を使うな」と書くフラグ
 * である。読み捨てると、SDK が知らない拡張で絞られた証明書 — 例えば用途を限定した
 * extendedKeyUsage や、加盟国ごとのポリシー制約を critical で載せた Qualified Certificate — を
 * 「制限が無いもの」として通してしまう。RFC 5280 §6.1.4 (f) の path validation は、解釈しない
 * critical 拡張を 1 つでも持つ証明書を**拒否**することを要求する。
 *
 * {@link RECOGNIZED_EXTENSION_OIDS} には、SDK が実際に判断に使う拡張を列挙する。
 * basicConstraints / keyUsage / nameConstraints は証明書チェーンの制約に使う。subjectAltName は名前制約の照合や RP の origin 取得に、
 * subjectDirectoryAttributes は RP の要求属性を認可する際に使う。
 * RFC 5280 §6.1.4 (f) が問うのは
 * 「この証明書を使う側がその制限を理解しているか」であり、理解している拡張を拒否理由にすると、
 * 正当な証明書を診断不能な `trusted:false` で落とすだけになる（RFC 5280 §4.2.1.8 は
 * subjectDirectoryAttributes を non-critical と定めているので、これで緩む相手は規格非適合の
 * 証明書に限られる）。
 *
 * `verifyCertificateChain` は呼び出し元にかかわらず同じ拡張集合を使う。subjectDirectoryAttributes を読み取るのは rp-access である。
 * 分けなかったのは、経路ごとの集合にすると「どの経路から来たか」で同じ証明書の受理可否が変わり、
 * 呼び出し側に証明書の受理条件を観測させる差になるからである。緩む相手は、RFC 5280 §4.2.1.8 /
 * §4.2.1.6 が non-critical を要求する拡張を critical で載せた規格非適合の証明書に限られる。
 *
 * 逆に、読まない拡張を「知っている」ことにすると、このモジュールは何も守らなくなる（critical を
 * 読む意味が無くなる）ので、chain.ts が「明示的に行わない検査」と書いた拡張
 * （extendedKeyUsage / certificatePolicies / policyConstraints / inhibitAnyPolicy 等）は
 * critical で載っていれば拒否側に倒す。
 *
 * **Trust Anchor には課さない。** `path-constraints.ts` の他の述語と同じ理由で、Anchor は
 * 呼び出し側が設定した信頼の起点であり、攻撃者が差し込める `intermediatesDer` とは前提が違う。
 * 課す / 課さないの判断は呼び出し元（`etsi-tsl/chain.ts`）が持つ。
 *
 * セキュリティ上の注意:
 * - 例外を投げず真偽値で返す。戻り値に証明書本文 / DN / 鍵素材・拡張 OID を含めない。
 */

import { OID_BASIC_CONSTRAINTS, OID_KEY_USAGE } from './ca-constraints.js';
import { OID_NAME_CONSTRAINTS } from './name-constraints.js';
import { type CertificateExtensions, OID_SUBJECT_ALT_NAME, OID_SUBJECT_DIR_ATTRS } from './san.js';

/**
 * SDK が値を読んで判断に使う拡張の OID（RFC 5280 §6.1.4 (f) の "recognized"）。
 *
 * basicConstraints、keyUsage、nameConstraints、subjectAltName、subjectDirectoryAttributes を含む。
 */
const RECOGNIZED_EXTENSION_OIDS: ReadonlySet<string> = new Set([
  OID_BASIC_CONSTRAINTS,
  OID_KEY_USAGE,
  OID_NAME_CONSTRAINTS,
  OID_SUBJECT_ALT_NAME,
  OID_SUBJECT_DIR_ATTRS,
]);

/**
 * 解釈できない critical 拡張を持つか（RFC 5280 §6.1.4 (f)）。
 *
 * @param extensions `tryCertificateExtensions` の戻り値（読めなければ `undefined`）。
 * @returns 解釈できない critical 拡張があれば `true`。拡張そのものを読めなかった場合も `true`
 *   （critical の有無すら確かめられていないので fail-closed）。
 */
export function hasUnrecognizedCriticalExtension(
  extensions: CertificateExtensions | undefined,
): boolean {
  if (extensions === undefined) {
    return true;
  }
  for (const oid of extensions.criticalOids) {
    if (!RECOGNIZED_EXTENSION_OIDS.has(oid)) {
      return true;
    }
  }
  return false;
}
