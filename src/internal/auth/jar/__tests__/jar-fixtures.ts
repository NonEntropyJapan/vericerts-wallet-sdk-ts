/**
 * JAR 署名検証のテストフィクスチャ。
 *
 * RP Access Certificate の鍵で Request Object に署名し、JWS ヘッダの `x5c` に証明書チェーンを載せる。
 * 証明書の DER 組み立ては `trust/rp-access/__tests__/fixtures.ts` の `makeRpCertificate` を
 * 再利用する（DER ビルダを複製すると、証明書の作り方が 2 通りに分かれて「テストだけ通る
 * 証明書」が生まれる）。
 *
 * ECDSA の JWS 署名は RFC 7515 が raw(P1363・r||s) を要求するため `dsaEncoding: 'ieee-p1363'`
 * で署名する（Node の既定は DER）。`trust/etsi-tsl/verify.ts` は DER も受理するが、テストは
 * ワイヤ上の正しい形を通すべきなので raw を使う。
 */

import { createSign, type KeyObject } from 'node:crypto';
import { base64, base64urlnopad } from '@scure/base';
import type { QtspServiceCertificate } from '../../../trust/etsi-tsl/index.js';
import {
  makeRpCertificate,
  type RpCertFixture,
} from '../../../trust/rp-access/__tests__/fixtures.js';

/** テストで用いる Verifier のドメイン（`client_id` / `response_uri` / SAN が揃う先）。 */
export const CLIENT_ID = 'https://verifier.example.com';
/** 参照形式の `request_uri`。 */
export const REQUEST_URI = 'https://verifier.example.com/request/123';

/** 署名済み JAR を作れる Verifier 一式（CA / RP 証明書 / Trust Anchor）。 */
export interface JarSigner {
  readonly ca: RpCertFixture;
  readonly rp: RpCertFixture;
  readonly anchors: readonly QtspServiceCertificate[];
  readonly kind: 'ec' | 'rsa';
}

/** `x5c` に載せる標準 base64（RFC 7515 §4.1.6）。 */
export function toX5cEntry(der: Uint8Array): string {
  return base64.encode(der);
}

/**
 * CA と、その CA が発行した RP Access Certificate を作る。
 *
 * @param opts `origin` は証明書 SubjectAltName（URI）。省略時は `CLIENT_ID`。
 */
export function makeJarSigner(opts?: {
  readonly origin?: string;
  readonly kind?: 'ec' | 'rsa';
  readonly notAfter?: Date;
  /** RP 証明書の notBefore（省略時は 1 日前）。 */
  readonly notBefore?: Date;
  /** Trust Anchor（CA）証明書の notAfter（省略時は 1 日後）。 */
  readonly caNotAfter?: Date;
}): JarSigner {
  const kind = opts?.kind ?? 'ec';
  const ca = makeRpCertificate({
    subject: { organizationName: 'Test QTSP CA', country: 'DE' },
    kind,
    serial: 100,
    ...(opts?.caNotAfter !== undefined ? { notAfter: opts.caNotAfter } : {}),
  });
  const rp = makeRpCertificate({
    subject: { organizationName: 'Example Verifier', country: 'DE' },
    kind,
    origin: opts?.origin ?? CLIENT_ID,
    serial: 101,
    ...(opts?.notAfter !== undefined ? { notAfter: opts.notAfter } : {}),
    ...(opts?.notBefore !== undefined ? { notBefore: opts.notBefore } : {}),
    issuer: { name: ca.subjectName, privateKey: ca.privateKey, kind },
  });
  return { ca, rp, anchors: [{ certDer: ca.der, granted: true }], kind };
}

/**
 * JAR ペイロードの既定クレーム（`iss == client_id`、同一オリジンの `response_uri`）。
 *
 * `exp` は `verifyJarSignature` の必須クレームなので既定で
 * 載せる。値は呼び出し時刻から 5 分後で、テストが実時計で落ちない程度に近い未来を取る
 * （固定値にすると時間の経過でテストが腐る）。
 */
export function jarClaims(overrides?: Record<string, unknown>): Record<string, unknown> {
  return {
    iss: CLIENT_ID,
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: `${CLIENT_ID}/callback`,
    nonce: 'n-0S6_WzA2Mj-0123456789',
    state: 'af0ifjsldkj',
    exp: Math.floor(Date.now() / 1000) + 300,
    ...overrides,
  };
}

/** JWS ヘッダ / ペイロードを base64url 直列化し signing-input を返す。 */
function signingInput(header: object, payload: object): string {
  const enc = (value: object): string =>
    base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(value)));
  return `${enc(header)}.${enc(payload)}`;
}

/** RP 秘密鍵で signing-input を署名する（ECDSA は raw(P1363)）。 */
function signRaw(input: string, privateKey: KeyObject, kind: 'ec' | 'rsa'): Uint8Array {
  const signer = createSign('SHA256');
  signer.update(input);
  signer.end();
  const signature =
    kind === 'ec'
      ? signer.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' })
      : signer.sign(privateKey);
  return new Uint8Array(signature);
}

/**
 * 署名済み JAR（コンパクト JWS）を組み立てる。
 *
 * @param verifier `makeJarSigner` の戻り値。
 * @param opts `claims` 上書き・`header` 上書き（`alg` / `x5c` の差し替え）・
 *             `tamper` で署名後にペイロードを差し替える（署名不正の再現）。
 */
export function signJar(
  verifier: JarSigner,
  opts?: {
    readonly claims?: Record<string, unknown>;
    readonly header?: Record<string, unknown>;
    readonly omitX5c?: boolean;
    readonly tamperedClaims?: Record<string, unknown>;
  },
): string {
  const alg = verifier.kind === 'ec' ? 'ES256' : 'RS256';
  const header: Record<string, unknown> = {
    alg,
    typ: 'oauth-authz-req+jwt',
    ...(opts?.omitX5c === true ? {} : { x5c: [toX5cEntry(verifier.rp.der)] }),
    ...opts?.header,
  };
  const claims = opts?.claims ?? jarClaims();
  const input = signingInput(header, claims);
  const signature = signRaw(input, verifier.rp.privateKey, verifier.kind);
  const signed = `${input}.${base64urlnopad.encode(signature)}`;
  if (opts?.tamperedClaims === undefined) {
    return signed;
  }
  // 署名を保ったままペイロードだけ差し替える（= 署名検証で落ちるべき入力）。
  const [headerSeg, , signatureSeg] = signed.split('.') as [string, string, string];
  const tampered = base64urlnopad.encode(
    new TextEncoder().encode(JSON.stringify(opts.tamperedClaims)),
  );
  return `${headerSeg}.${tampered}.${signatureSeg}`;
}
