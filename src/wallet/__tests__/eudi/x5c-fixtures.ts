/**
 * `x5c` による Issuer 鍵解決のテスト用フィクスチャ。
 *
 * 実鍵素材のみを使う。CA・Issuer の X.509 v3 証明書は `trust/rp-access` のテストビルダで本物の
 * DER を生成し（SubjectAltName の URI と有効期間・署名まで実データ）、その Issuer 鍵で SD-JWT VC
 * の Issuer-signed JWT に署名する。モック検証器は使わない — チェーン検証・SAN 突き合わせ・
 * 署名検証のいずれかを素通りさせると、テストだけが緑のまま fail-open が残るためである。
 */

import type { KeyObject } from 'node:crypto';
import { base64, base64urlnopad } from '@scure/base';
import type { QtspServiceCertificate } from '../../../internal/trust/etsi-tsl/index.js';
import { makeRpCertificate } from '../../../internal/trust/rp-access/__tests__/fixtures.js';

/** テストで用いる PID Provider の HTTPS 識別子（`iss` と Issuer 証明書 SAN が揃う先）。 */
export const X5C_ISSUER = 'https://pid-provider.example.eu';

/** 生成した Issuer チェーン一式。 */
export interface IssuerChainFixture {
  /** `createWallet({ issuerTrustAnchors })` に渡す Trust Anchor（CA 自己署名証明書）。 */
  readonly anchors: readonly QtspServiceCertificate[];
  /** Issuer-signed JWT ヘッダに載せる `x5c`（標準 base64 の DER 配列）。 */
  readonly x5c: readonly string[];
  /**
   * SD-JWT VC の署名に使う P-256 秘密鍵。
   *
   * `kind: 'ec'`（既定）では Issuer 証明書の鍵そのもの。`kind: 'rsa'` では証明書の鍵を ES256 の
   * 署名器に渡せないため別鍵を返す — その場合は鍵解決（SPKI → JWK）が先に落ちるので、署名鍵が
   * 証明書と対応しないことは結果に影響しない。
   */
  readonly signingKey: Uint8Array;
}

/** RSA leaf の検証を組み立てるための、証明書とは無関係な P-256 秘密鍵。 */
const UNRELATED_P256_PRIVATE_KEY = new Uint8Array(32).fill(11);

/** Node の EC 秘密鍵から生の 32 バイトスカラーを取り出す（SDK の署名器へ渡す形）。 */
function rawPrivateKey(key: KeyObject): Uint8Array {
  const jwk = key.export({ format: 'jwk' }) as { d?: string };
  return base64urlnopad.decode(jwk.d as string);
}

/** {@link makeIssuerChain} の入力（既定から外した部分だけを指定する）。 */
export interface IssuerChainOverrides {
  /** Issuer 証明書の SubjectAltName（URI）。既定は {@link X5C_ISSUER}。 */
  readonly san?: string;
  /** Trust Anchor の `granted` フラグ。既定 `true`。 */
  readonly granted?: boolean;
  /** Issuer 証明書の鍵種別。既定 `'ec'`（P-256）。 */
  readonly kind?: 'ec' | 'rsa';
}

/**
 * 「CA（Trust Anchor）→ Issuer 証明書」の 2 段チェーンを生成する。
 *
 * @param overrides SAN / granted / 鍵種別の差し替え。
 * @returns Trust Anchor・`x5c`・Issuer 署名鍵。
 */
export function makeIssuerChain(overrides: IssuerChainOverrides = {}): IssuerChainFixture {
  const ca = makeRpCertificate({ subject: { organizationName: 'QTSP CA' }, kind: 'ec' });
  const leaf = makeRpCertificate({
    subject: { organizationName: 'PID Provider' },
    kind: overrides.kind ?? 'ec',
    origin: overrides.san ?? X5C_ISSUER,
    issuer: { name: ca.subjectName, privateKey: ca.privateKey, kind: 'ec' },
  });
  return {
    anchors: [{ certDer: ca.der, granted: overrides.granted ?? true }],
    // RFC 7515 §4.1.6 の `x5c` は base64url ではなく**標準 base64**。
    x5c: [base64.encode(leaf.der), base64.encode(ca.der)],
    signingKey:
      overrides.kind === 'rsa' ? UNRELATED_P256_PRIVATE_KEY : rawPrivateKey(leaf.privateKey),
  };
}
