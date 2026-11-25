/**
 * FC-11（鍵無効化宣言 `revoked_keys`）の VC 検証経路への適用を検証するテストの共有フィクスチャ。
 *
 * Issuer の鍵無効化宣言（`revoked_keys`）と発行時刻に基づく拒否（FC-11）が対象。
 *
 * `TrustChain` は `buildTrustChain` を通さずオブジェクトリテラルで組み立てる。ここで検証したいのは
 * 「chain に載った宣言が VC 検証経路で強制されるか」であり、chain 構築そのもの（署名・fetch）は
 * `trust/federation/__tests__` が別途担保しているためである。署名は実鍵（P-256）で行いモックしない。
 *
 * テストケースは含まない（Linterly の 1 ファイル 300 行上限に収めるための分離）。
 */

import { expect } from 'bun:test';
import { type ErrorCode, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import type {
  ScopedRevokedKeyDeclaration,
  TrustChain,
  TrustChainNode,
} from '../../../trust/federation/federation-types.js';
import type { IssuerTrustOption } from '../../issuer-key-revocation.js';
import { createSdJwt } from '../../sdjwt/sdjwt.js';
import { verifySdJwt } from '../../sdjwt/verify.js';
import { issueCredential } from '../../vc/issue.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../vc/signer.js';
import type { VerifiableCredential } from '../../vc/vc.js';
import { verifyCredential } from '../../vc/verify.js';

/** 検証時刻（2026-01-01T00:00:00Z）。無効化時刻より十分後に置く。 */
export const NOW = 1_767_225_600;

/** 無効化時刻 T。この時刻**以降**に発行された VC を拒否する（境界を含む）。 */
export const REVOKED_AT_ISO = '2025-12-01T00:00:00Z';
export const REVOKED_AT = Math.floor(Date.parse(REVOKED_AT_ISO) / 1000);
/** 漏洩前（T-1 秒）の発行日時。巻き添えにしてはならない。 */
export const BEFORE_REVOKED_ISO = '2025-11-30T23:59:59Z';
export const BEFORE_REVOKED = Math.floor(Date.parse(BEFORE_REVOKED_ISO) / 1000);
/** 漏洩後（T+1 秒）の発行日時。 */
export const AFTER_REVOKED_ISO = '2025-12-01T00:00:01Z';
export const AFTER_REVOKED = Math.floor(Date.parse(AFTER_REVOKED_ISO) / 1000);
/** VC の有効期限（`NOW` より十分後）。 */
const EXPIRATION_ISO = '2027-01-01T00:00:00Z';

/** 宣言対象の Issuer（Trust Chain の leaf を想定）。 */
export const ISSUER_ID = 'https://issuer.example.eu';
/** 同じ `kid` を使う**別**エンティティ。巻き添え（kid 衝突）の回帰に使う。 */
export const OTHER_ISSUER_ID = 'https://other-issuer.example.eu';
/** leaf ではない中間エンティティ。`issuerTrust.issuer` の明示指定に使う。 */
export const INTERMEDIATE_ID = 'https://intermediate.example.eu';
const ANCHOR_ID = 'https://anchor.example.eu';

/** VC の署名に使う `kid`。 */
export const SIGNING_KID = 'issuer-1';
/** 署名には使わない別の `kid`（宣言対象外であることの確認に使う）。 */
export const UNRELATED_KID = 'issuer-0';
/**
 * 攻撃者が JWS ヘッダに詐称する、どこにも宣言されていない `kid`。
 *
 * FC-11 の脅威モデルでは署名者自身が失効鍵の保有者なので、ヘッダの `kid` は自由に書ける。
 */
export const FORGED_KID = 'issuer-1-prime';

/** SD-JWT VC の `vct`。 */
export const VCT = 'https://example.com/credentials/identity';

/** テスト用の固定秘密鍵（P-256）。 */
const ISSUER_PRIVATE_KEY = new Uint8Array(32).fill(7);

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

/** 発行者の検証用公開鍵 JWK。 */
export const ISSUER_JWK: PublicKeyJwk = toJwk(getP256PublicKey(ISSUER_PRIVATE_KEY, false));

/**
 * 発行者の署名鍵を返す。
 *
 * `kid` を渡さない呼び出しは JWS ヘッダに `kid` を出力しない（`buildJwsHeader` の仕様）。
 * fail-closed（`kid` 欠落）の検証に使う。
 */
export function issuerSigner(kid?: string): CredentialSigner {
  const base = createPrivateKeySigner(ISSUER_PRIVATE_KEY, 'ES256');
  return kid === undefined ? base : { ...base, kid };
}

/** 鍵無効化宣言（`sub` 紐付き）を組み立てる。 */
export function declaration(
  sub: string,
  kid: string = SIGNING_KID,
  revokedAt: number = REVOKED_AT,
): ScopedRevokedKeyDeclaration {
  return { sub, kid, revoked_at: revokedAt, reason: 'key_compromise' };
}

/**
 * 上位（Trust Anchor）が `sub` について署名した Subordinate Statement ノードを組み立てる。
 *
 * FC-11 の突合キーはここの `jwks` から**鍵素材**で引かれる。宣言（`revoked_keys`）と同じ権威に
 * 由来し攻撃者が改竄できない唯一の「鍵素材 ⇔ `kid`」対応であるため、テストでも実際にこのノードを
 * 積む（`nodes: []` の chain は「上位が裏付けていない鍵」を意味し fail-closed になる）。
 */
function subordinateNode(sub: string, kids: readonly string[]): TrustChainNode {
  return {
    iss: ANCHOR_ID,
    sub,
    kind: 'subordinate-statement',
    statement: {
      iss: ANCHOR_ID,
      sub,
      iat: BEFORE_REVOKED,
      exp: NOW + 86_400,
      jwks: { keys: kids.map((kid) => ({ ...ISSUER_JWK, kid })) },
    },
  };
}

/**
 * 宣言と、`ISSUER_JWK` の裏付けを載せた `TrustChain` を組み立てる。
 *
 * 既定では leaf・中間・別エンティティのいずれについても `SIGNING_KID` で `ISSUER_JWK` を裏付ける。
 * `attestedKids` を明示すると裏付けの `kid` を差し替えられる（空配列なら裏付け無し＝ fail-closed）。
 */
export function trustChain(
  revokedKeys: readonly ScopedRevokedKeyDeclaration[],
  opts: {
    readonly leaf?: string;
    readonly valid?: boolean;
    readonly attestedKids?: readonly string[];
  } = {},
): TrustChain {
  const leaf = opts.leaf ?? ISSUER_ID;
  const kids = opts.attestedKids ?? [SIGNING_KID];
  const subjects = [...new Set([leaf, INTERMEDIATE_ID, OTHER_ISSUER_ID])];
  const nodes = subjects.map((sub) => subordinateNode(sub, kids));
  return {
    valid: opts.valid ?? true,
    leaf,
    trustAnchor: ANCHOR_ID,
    nodes,
    length: nodes.length,
    revokedKeys,
  };
}

/** サンプル VC（`issuanceDate` が JWT-VC の `nbf` になる）。 */
function sampleVc(issuanceDate: string): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate,
    expirationDate: EXPIRATION_ISO,
    id: 'urn:uuid:436',
  };
}

/**
 * JWT-VC を発行する。`issueCredential` は `nbf = issuanceDate` と `iat = 発行時刻` を設定する。
 *
 * FC-11 は JWT-VC の発行時刻を `nbf` から取る（`iat` はフォールバック）ため、ここでは発行時刻を
 * `issuanceDate` に合わせておく（検証時刻 `NOW` から見て未来の `iat` にならないようにする意味もある）。
 */
export function issueJwtVc(issuanceDate: string, kid?: string): string {
  return issueCredential(sampleVc(issuanceDate), issuerSigner(kid), {
    nowSeconds: Math.floor(Date.parse(issuanceDate) / 1000),
  });
}

/**
 * 任意の header / payload を有効署名で JWT にする（`nbf` / `iat` 欠落の検証用）。
 *
 * `issueCredential` は必ず `nbf` を設定するため、発行時刻が取れない JWT-VC は手組みするしかない。
 */
export function signJwt(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const b64u = (text: string): string => Buffer.from(text).toString('base64url');
  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const signature = issuerSigner().sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
}

/**
 * 発行済み JWT-VC の payload に任意のクレームを後付けして、同じ実鍵で再署名する。
 *
 * FC-11 のバックデート攻撃の再現に使う。失効鍵の保有者は署名鍵を持っているので、`nbf` /
 * `vc.issuanceDate` を現在時刻に保ったまま過去の `iat` を足した JWT-VC を自由に作れる。
 * 得られる JWT は署名・時刻クレーム・envelope ↔ body 整合のいずれも成立した**正当な** JWT-VC
 * であり、FC-11 の突合以外では落ちない。
 */
export function reissueJwtVcWithClaims(
  jwt: string,
  extraClaims: Readonly<Record<string, unknown>>,
): string {
  const [headerPart, payloadPart] = jwt.split('.');
  const decode = (part: string | undefined): Record<string, unknown> =>
    JSON.parse(Buffer.from(part ?? '', 'base64url').toString('utf8')) as Record<string, unknown>;
  return signJwt(decode(headerPart), { ...decode(payloadPart), ...extraClaims });
}

/**
 * SD-JWT VC を発行する。`claims` の `iat` が payload の発行時刻になる。
 *
 * `createSdJwt` は `claims` に `iat` が無ければ既定で `nowSeconds`（ここでは `NOW`）を設定するため、
 * **発行時刻を持たない**（= 旧 Issuer 由来の）SD-JWT VC を作るには `{ iat: undefined }` を明示する
 * （`JSON.stringify` が値 `undefined` のキーを落とすため payload から `iat` が消える）。
 */
export function issueSdJwtVc(claims: Readonly<Record<string, unknown>>, kid?: string): string {
  return createSdJwt(issuerSigner(kid), {
    vct: VCT,
    issuer: 'did:example:issuer',
    disclosureClaims: ['name'],
    claims: { name: 'Alice', ...claims },
    salts: { name: 'salt-436' },
    nowSeconds: NOW,
  });
}

/** JWT-VC を検証する（`issuerTrust` 未指定なら FC-11 判定は走らない）。 */
export function verifyJwtVc(jwt: string, issuerTrust?: IssuerTrustOption): void {
  verifyCredential(jwt, { key: { publicKeyJwk: ISSUER_JWK }, nowSeconds: NOW, issuerTrust });
}

/** SD-JWT VC を検証する（`issuerTrust` 未指定なら FC-11 判定は走らない）。 */
export function verifySdJwtVc(sdJwt: string, issuerTrust?: IssuerTrustOption): void {
  verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW, issuerTrust });
}

/**
 * 発行者の検証用公開鍵 JWK に `kid` ラベルを付けた版。
 *
 * 鍵素材は `ISSUER_JWK` と同一なので署名検証は成立する。突合キーが JWK の `kid` ラベルでは決まらず
 * （ラベルは DID Document 経由で発行者＝攻撃者が付け替えられる）、上位が署名した JWKS を鍵素材で
 * 引いて決まることの検証に使う。
 */
export function issuerJwkWithKid(kid: string): PublicKeyJwk {
  return { ...ISSUER_JWK, kid };
}

/** 上位の JWKS に載っていない別の鍵（裏付けを引けない検証鍵の再現に使う）。 */
const UNATTESTED_PRIVATE_KEY = new Uint8Array(32).fill(11);
const UNATTESTED_JWK: PublicKeyJwk = toJwk(getP256PublicKey(UNATTESTED_PRIVATE_KEY, false));

/** 上位が裏付けていない鍵で JWT-VC を発行し、その鍵で検証する。 */
export function verifyJwtVcSignedByUnattestedKey(
  issuanceDate: string,
  issuerTrust: IssuerTrustOption,
): void {
  const signer = createPrivateKeySigner(UNATTESTED_PRIVATE_KEY, 'ES256');
  const jwt = issueCredential(
    sampleVc(issuanceDate),
    { ...signer, kid: SIGNING_KID },
    {
      nowSeconds: Math.floor(Date.parse(issuanceDate) / 1000),
    },
  );
  verifyCredential(jwt, { key: { publicKeyJwk: UNATTESTED_JWK }, nowSeconds: NOW, issuerTrust });
}

/** 上位が裏付けていない鍵で SD-JWT VC を発行し、その鍵で検証する。 */
export function verifySdJwtVcSignedByUnattestedKey(
  claims: Readonly<Record<string, unknown>>,
  issuerTrust: IssuerTrustOption,
): void {
  const signer = createPrivateKeySigner(UNATTESTED_PRIVATE_KEY, 'ES256');
  const sdJwt = createSdJwt(
    { ...signer, kid: SIGNING_KID },
    {
      vct: VCT,
      issuer: 'did:example:issuer',
      disclosureClaims: ['name'],
      claims: { name: 'Alice', ...claims },
      salts: { name: 'salt-436' },
      nowSeconds: NOW,
    },
  );
  verifySdJwt(sdJwt, { issuerKey: UNATTESTED_JWK, nowSeconds: NOW, issuerTrust });
}

/** JWT-VC を `kid` 付き検証鍵で検証する。 */
export function verifyJwtVcWithKeyKid(
  jwt: string,
  keyKid: string,
  issuerTrust?: IssuerTrustOption,
): void {
  const key = { publicKeyJwk: issuerJwkWithKid(keyKid) };
  verifyCredential(jwt, { key, nowSeconds: NOW, issuerTrust });
}

/** SD-JWT VC を `kid` 付き検証鍵で検証する。 */
export function verifySdJwtVcWithKeyKid(
  sdJwt: string,
  keyKid: string,
  issuerTrust?: IssuerTrustOption,
): void {
  verifySdJwt(sdJwt, { issuerKey: issuerJwkWithKid(keyKid), nowSeconds: NOW, issuerTrust });
}

/** 同期呼び出しが指定コードの `VericertsError` を投げることを検証する。 */
export function expectThrowCode(run: () => unknown, code: ErrorCode): void {
  let caught: unknown;
  try {
    run();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(code);
}
