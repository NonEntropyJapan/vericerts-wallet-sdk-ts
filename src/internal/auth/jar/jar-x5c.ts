/**
 * JAR JOSE Header の `x5c` を証明書チェーンに展開し、JWS の `alg` を証明書署名アルゴリズムに対応付ける。
 *
 * **なぜ抽出を独立モジュールにするか。** `x5c`（RFC 7515 §4.1.6）は**攻撃者が中身を選べる
 * ヘッダ値**である。Verifier を騙る側は好きな証明書チェーンを好きな順で並べられるので、
 * 抽出は「配列であること・要素が非空文字列であること・base64（**標準アルファベット**）として
 * デコードできること」をすべて満たさない限り 1 件も採用してはならない。この入口検査を
 * 検証本体（`jar-signature.ts`）と混ぜると、どの条件が効いているのかがテストから見えなくなる。
 *
 * **base64url ではなく標準 base64 である。** RFC 7515 §4.1.6 は `x5c` を「base64-encoded
 * (**not** base64url-encoded) DER」の配列と定めている。JWS の他のセグメント（header /
 * payload / signature）だけが base64url なので、ここで `base64urlnopad` を使うと `+` / `/` を
 * 含む正当な証明書が「不正」として落ち、逆に取りこぼしを許す実装では別の値が通る。
 *
 * セキュリティ上の注意:
 * - 戻り値・例外に証明書本文（DER）・DN・鍵素材を含めない。判定は真偽値と DER バイト列のみ。
 */

import { base64 } from '@scure/base';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { MAX_INTERMEDIATES } from '../../trust/etsi-tsl/chain.js';
import type { CertSignatureAlg } from '../../trust/etsi-tsl/index.js';

/**
 * JAR JWS の `alg` → 証明書署名アルゴリズム（`trust/etsi-tsl` の `verifySignature` が解する形）。
 *
 * **本マップが SDK の alg 許可リストそのものである。** ここに無い `alg`（`none` / `HS256` の
 * ような MAC / `PS256` のような RSASSA-PSS / `EdDSA`）は署名検証に到達させず拒否する。
 * X.509 の RP Access Certificate が載せる公開鍵は `trust/etsi-tsl/x509.ts` が対応する
 * RSA（sha256WithRSAEncryption）と EC P-256（ecdsa-with-SHA256）の 2 種であり、JAR の署名鍵は
 * その証明書の鍵なので、対応する JWS alg も `RS256` / `ES256` の 2 つに限られる。
 *
 * `alg=none` を明示的に列挙しないのは、**許可リスト方式では列挙しないこと自体が拒否**であり、
 * 拒否リストに 1 項目足し忘れる余地を残さないためである。
 */
const CERT_ALG_BY_JAR_ALG: Readonly<Record<string, CertSignatureAlg>> = {
  ES256: 'ECDSA-P256-SHA256',
  RS256: 'RSASSA-PKCS1-v1_5-SHA256',
};

/** `x5c` から取り出したチェーン（先頭 = 署名者のリーフ証明書）。 */
export interface X5cChain {
  /** `x5c[0]`。JAR JWS を署名した RP Access Certificate。 */
  readonly leafDer: Uint8Array;
  /** `x5c[1..]`。リーフから Trust Anchor へ辿る中間 CA 証明書（順不同として扱う）。 */
  readonly intermediatesDer: readonly Uint8Array[];
}

/**
 * 受け取った `alg` 文字列を SDK が対応する証明書署名アルゴリズムへ写す。
 *
 * `alg` は呼び出し側が `jwsAlgOf` で JOSE Header から取り出したものを渡す（同じキーを二度読み
 * しないため、本関数は `header` に触れない）。
 *
 * @param alg `jwsAlgOf` が返した JWS の `alg`（欠落・非文字列・空白のみなら `undefined`）。
 * @returns 対応する証明書署名アルゴリズム。`alg` が `undefined` または未対応なら `undefined`。
 */
export function certSignatureAlgOf(alg: string | undefined): CertSignatureAlg | undefined {
  if (alg === undefined) {
    return undefined;
  }
  // 許可リストは own 限定で引く。鎖読みだと、許可リストに**無い** `alg`（`none` / MAC など）が
  // 汚染された `Object.prototype` の値を拾い、攻撃者が選んだ検証アルゴリズムで照合される。
  return ownProperty<CertSignatureAlg>(CERT_ALG_BY_JAR_ALG, alg);
}

/**
 * JWS ヘッダの `alg` をそのまま（正規化せずに）返す。
 *
 * `request_object_signing_alg_values_supported` との照合は
 * **JWS の alg 名**で行う必要があるため、`certSignatureAlgOf` の写像後の名前とは別に必要になる。
 *
 * @param header デコード済み JOSE Header。
 * @returns `alg` の値。欠落・非文字列・空白のみなら `undefined`。
 */
export function jwsAlgOf(header: object): string | undefined {
  const alg = ownProperty<unknown>(header, 'alg');
  return isNonBlankString(alg) ? alg : undefined;
}

/**
 * JOSE Header の `x5c` を証明書チェーンへ展開する（RFC 7515 §4.1.6）。
 *
 * 次のいずれかを満たさない `x5c` は**チェーンを 1 件も返さない**（fail-closed）:
 * 配列でない / 空配列 / 要素に非文字列・空白のみを含む / 標準 base64 としてデコードできない。
 * 「先頭だけ読めれば残りは無視する」ような部分採用をしないのは、中間証明書が 1 つ壊れている
 * チェーンをリーフのみのチェーンとして扱うと、**Trust Anchor へ到達しないはずの証明書が
 * 「中間なしで到達した」形に化ける**余地を作るためである。
 *
 * @param header デコード済み JOSE Header。
 * @returns リーフと中間証明書の DER。`x5c` が上記条件を満たさない場合は `undefined`。
 */
export function extractX5cChain(header: object): X5cChain | undefined {
  // `x5c` も own 限定で読む。鎖読みだと `x5c` を**持たない**（= 署名者証明書を添付していない）
  // JAR が汚染された `Object.prototype.x5c` を掴み、攻撃者が用意した証明書で検証される。
  const raw = ownProperty<unknown>(header, 'x5c');
  // 枚数は base64 デコードの**前**に O(1) で課す。`verifyCertificateChain` は中間証明書を
  // `MAX_INTERMEDIATES` 枚までしか受け付けず、それを超える x5c は常に拒否されるので、極小エントリを
  // 大量に並べた JAR のデコード・指紋計算・キャッシュ保持に資源を使わない（リーフ分で +1）。
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_INTERMEDIATES + 1) {
    return undefined;
  }
  const ders: Uint8Array[] = [];
  for (const entry of raw) {
    if (!isNonBlankString(entry)) {
      return undefined;
    }
    let der: Uint8Array;
    try {
      // RFC 7515 §4.1.6 は標準 base64（パディング付き）。base64url ではない。
      der = base64.decode(entry.trim());
    } catch {
      return undefined;
    }
    if (der.length === 0) {
      return undefined;
    }
    ders.push(der);
  }
  const [leafDer, ...intermediatesDer] = ders as [Uint8Array, ...Uint8Array[]];
  return { leafDer, intermediatesDer };
}
