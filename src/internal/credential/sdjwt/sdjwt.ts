/**
 * SD-JWT（Selective Disclosure JWT）/ SD-JWT VC の発行・分解・選択的開示プリミティブ。
 *
 * IETF draft-ietf-oauth-selective-disclosure-jwt / draft-ietf-oauth-sd-jwt-vc 準拠。
 *
 * シリアライズ形式:
 *
 * ```text
 * <Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~[<KB-JWT>]
 * ```
 *
 * Issuer-signed JWT は既存の `CredentialSigner`（`signer.ts`）でコンパクト JWS として署名する
 * （`issue.ts` と同方針。`jose` は使わない）。本モジュールは発行（`createSdJwt`）・分解
 * （`parseSdJwt`）・選択的開示（`selectDisclosures`）を担い、検証は `sdjwt-verify.ts` が担う。
 *
 * KMS / HSM のような非同期署名にも対応するため、`createSdJwtAsync` を併せて提供する。
 * Disclosure 生成・payload 組み立ては同期版と共有し、署名の await 有無のみが異なる。
 *
 * SD-JWT VC 固有クレーム:
 * - `vct`（Verifiable Credential Type）: VC Type URI。発行時に付与し検証時に照合する。
 * - `cnf`（confirmation）: Holder 公開鍵バインド（`{ jwk }`）。KB-JWT 検証の鍵源になる。
 * - `status`（Token Status List 参照）: `{ status_list: { idx, uri } }`。構造保持と参照解決まで。
 *
 * JWS ヘッダの `typ` は既定で `dc+sd-jwt`（draft-ietf-oauth-sd-jwt-vc / HAIP 1.0）。移行期間中の
 * 旧 `vc+sd-jwt` での発行は `CreateSdJwtOptions.typ` に明示指定した場合のみ（既定では発行しない）。
 * 受理可能な `typ` の定義は `typ.ts` が SSOT。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に salt・開示値・JWT を含めない。
 */

import { base64urlnopad } from '@scure/base';
import { base64urlText } from '../../base64url.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { assertEpochSeconds } from '../../primitives/option-guard.js';
import { defineDataProperty } from '../../prototype-safety/define-data-property.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { type AnyCredentialSigner, buildJwsHeader, type CredentialSigner } from '../vc/signer.js';
import { type Disclosure, decodeDisclosure, encodeDisclosure } from './disclosure.js';
import { assertNoSpecialCategoryInSdJwtIssuance } from './gdpr-guard.js';
import { NON_DISCLOSABLE_CLAIMS } from './non-disclosable-claims.js';
import { resolveIssuanceTyp, type SdJwtVcTyp } from './typ.js';

/** SD-JWT VC の `cnf`（Holder 公開鍵バインド）クレーム。 */
export interface ConfirmationClaim {
  /** Holder の EC 公開鍵 JWK（KB-JWT 検証の鍵源）。 */
  readonly jwk: PublicKeyJwk;
}

/** SD-JWT VC の `status`（Token Status List 参照）クレーム。 */
export interface StatusReference {
  /** Status List Token 内の位置参照。 */
  readonly status_list: {
    /** Status List 内のビットインデックス。 */
    readonly idx: number;
    /** Status List Token の取得先 URL。 */
    readonly uri: string;
  };
}

/** SD-JWT VC 発行のオプション。 */
export interface CreateSdJwtOptions {
  /** Verifiable Credential Type URI（SD-JWT VC では必須）。 */
  readonly vct: string;
  /** 選択的開示するクレーム名（`claims` のうち `_sd` 配列に隠すもの）。 */
  readonly disclosureClaims: readonly string[];
  /** 平文クレーム（開示クレーム以外はそのまま payload に残す）。 */
  readonly claims: Readonly<Record<string, unknown>>;
  /** Holder 公開鍵バインド（`cnf`）。指定時に payload へ埋め込む。 */
  readonly cnf?: ConfirmationClaim;
  /** Token Status List 参照（`status`）。指定時に payload へ埋め込む。 */
  readonly status?: StatusReference;
  /** 発行者 DID（`iss`）。 */
  readonly issuer?: string;
  /** Disclosure ごとの固定 salt（テストの決定性のため注入可能。claimName → salt）。 */
  readonly salts?: Readonly<Record<string, string>>;
  /**
   * `iat`（発行時刻）に用いるエポック秒。既定は発行時の現在時刻。テストの決定性のため注入可能。
   * `claims` に `iat` を明示した場合は本項を無視し、そちらを payload に出力する
   * （`iat` / `exp` / `nbf` 等の登録済み JWT クレームは `disclosureClaims` に指定しても
   * 平文 payload に残る — `NON_DISCLOSABLE_CLAIMS`）。
   * `claims: { iat: undefined }` は「`iat` を出力しない」を意味する（旧 Issuer 相当の発行）。
   * スプレッドで意図せず `undefined` を混ぜると `iat` が消え 4014 判定が効かなくなる点に注意。
   */
  readonly nowSeconds?: number;
  /**
   * JWS ヘッダの `typ`。既定は `dc+sd-jwt`。
   * 旧 `vc+sd-jwt` での発行は明示指定した場合のみ（既定では発行しない）。
   */
  readonly typ?: SdJwtVcTyp;
}

/** SD-JWT を分解した構成要素。 */
export interface SdJwtParts {
  /** Issuer 署名済み JWT（コンパクト JWS）。 */
  readonly issuerJwt: string;
  /** 同梱された Disclosure 一覧。 */
  readonly disclosures: readonly Disclosure[];
  /** Key Binding JWT（あれば）。 */
  readonly keyBinding?: string;
}

/** ハッシュアルゴリズム識別子（`_sd_alg`）。本 SDK は SHA-256 固定。 */
export const SD_ALG = 'sha-256';

/** SD-JWT 発行の中間成果物（署名前）。同期版 / 非同期版で共有する。 */
interface SdJwtIssuanceParts {
  /** Issuer-signed JWT の signing-input（`base64url(header).base64url(payload)`）。 */
  readonly signingInput: string;
  /** `~` 連結済みの Disclosure 群（開示クレームが無ければ空文字列）。 */
  readonly disclosureParts: string;
}

/**
 * Disclosure と payload を組み立て、Issuer-signed JWT の signing-input を作る（署名前まで）。
 *
 * header は `{ alg, kid?, typ }`（`typ` の既定は `dc+sd-jwt`。旧 `vc+sd-jwt` は `opts.typ` で明示
 * 指定した場合のみ）。開示クレームは Disclosure へ分離し、その digest を
 * payload の `_sd` に格納する。残りのクレームと `vct` / `iss` / `cnf` / `status` は平文で残す。
 * `iat`（発行時刻）は `claims` に明示が無い限り既定で付与する。
 *
 * @param signer Issuer の JWT-VC 署名鍵（`alg` / `kid` を header に反映する）。
 * @param opts vct / 開示クレーム / 平文クレーム / cnf / status 等。
 * @returns signing-input と `~` 連結済み Disclosure 群。
 * @throws payload / Disclosure が Art.9 特別カテゴリ属性を含む場合（VericertsError、code `10607`）。
 */
function buildSdJwtIssuanceParts(
  signer: AnyCredentialSigner,
  opts: CreateSdJwtOptions,
): SdJwtIssuanceParts {
  const disclosures: Disclosure[] = [];
  const sd: string[] = [];
  const plainClaims: Record<string, unknown> = {};

  // 任意プロパティは自身のプロパティに限って読む。継承値を拾うと、その項目を省略
  // した正当な発行でも汚染値が **issuer-signed payload（= 署名対象）** に焼き付く（`cnf` = 攻撃者
  // の鍵への Holder バインド、`status` = 攻撃者の失効リスト参照、`salts` = 既知 salt による事前計算）。
  const cnf = ownProperty<ConfirmationClaim>(opts, 'cnf');
  const status = ownProperty<StatusReference>(opts, 'status');
  const issuer = ownProperty<string>(opts, 'issuer');
  const nowSeconds = ownProperty<number>(opts, 'nowSeconds');
  const salts = ownProperty<Readonly<Record<string, string>>>(opts, 'salts');

  // 「隠すクレームの一覧そのもの」も自身のプロパティに限って読む。従来は
  // 「隠せるクレーム」を塞いだが、`disclosureClaims` を**省略した**発行で汚染値が一覧に化けると、
  // 平文で載るはずのクレームが Disclosure へ移される。Holder はその Disclosure を落とせるため、
  // 検証結果からクレームが消える（発行者の意図しない選択的開示）。
  const disclosureSet = new Set(ownProperty<readonly string[]>(opts, 'disclosureClaims') ?? []);
  // クレーム集合そのものも own 限定で **1 度だけ** 読み、以降はこのローカルだけを使う。
  // 2 度読むと、1 回目（下の列挙）と 2 回目（既定 `iat` の判定）で別の値を返す own アクセサにより
  // 「列挙したクレーム集合」と「`iat` を明示したかの判定」が食い違う。1 回目に `iat` なし・
  // 2 回目に `iat` ありを返せば、平文にも既定にも `iat` が載らない**署名済み SD-JWT** ができ、
  // 未来 `iat` 判定（4014）がその資格情報について無言でスキップされる（`time-claims.ts` は
  // 存在するクレームしか評価しない）。逆順にすれば平文／Disclosure と `_sd` を食い違わせられる。
  // 鎖読み（`opts.claims`）をやめる意味もある: `claims` を**省略した**呼び出しに
  // `Object.prototype.claims` の汚染がクレーム集合を丸ごと供給する経路が消える。
  const claims = ownProperty<Readonly<Record<string, unknown>>>(opts, 'claims') ?? {};
  for (const [name, value] of Object.entries(claims)) {
    // 登録済み JWT クレーム（`iat` / `exp` / `nbf` / `iss` / `vct` / `cnf` / `status`）と構造
    // クレームは選択的開示の対象にしない（`iss` / `nbf` / `exp` / `cnf` / `vct` / `status` は
    // draft-ietf-oauth-sd-jwt-vc §2.2.2.3 の MUST NOT。`iat` は同 §2.2.2.3 が MAY とする中で
    // 本 SDK が追加で課すハードニング。詳細は `NON_DISCLOSABLE_CLAIMS` の注記）。
    // Disclosure 側へ回すと issuer-signed payload から平文が消え、`assertTimeClaims` の
    // 期限切れ判定（3024）・未発効判定（3025）・未来 `iat` 判定（4014）が無言でスキップされる
    // （time-claims.ts は「クレームが無ければ評価しない」設計のため）。
    if (disclosureSet.has(name) && !NON_DISCLOSABLE_CLAIMS.has(name)) {
      const salt = salts !== undefined ? ownProperty<string>(salts, name) : undefined;
      const disclosure = encodeDisclosure(name, value, salt);
      disclosures.push(disclosure);
      sd.push(disclosure.digest);
    } else {
      // `plainClaims[name] = value` は `name` が `__proto__` のとき own プロパティを作らず
      // オブジェクトのプロトタイプを差し替えるため、そのクレームが**署名済み payload から
      // 無言で消える**。`defineDataProperty`（記述子ごと `null` プロトタイプで組む
      // `Object.defineProperty` ラッパ）なら `__proto__` でも通常の own データプロパティに
      // なる（記述子リテラルを直接渡すと `Object.prototype.get` 汚染で
      // `defineProperty` 自体が TypeError を投げる）。
      defineDataProperty(plainClaims, name, value);
    }
  }

  const payload: Record<string, unknown> = {
    ...plainClaims,
    // `vct` は型上必須だが、省略された JS 呼び出しで継承値がそのまま**署名済み payload** の
    // 型識別子になる（検証側の `expectedVct` 突合を攻撃者が選んだ値で通す）。own 限定で読む。
    vct: ownProperty<string>(opts, 'vct'),
    _sd: sd,
    _sd_alg: SD_ALG,
  };
  // `iat` は SD-JWT VC の標準クレームで既定付与し、`claims` 明示時は上書きしない。
  // `in` はプロトタイプ鎖を辿るため `Object.hasOwn` を使う: 汚染下で未指定の発行を「明示済み」と
  // 誤判定すると既定 `iat` が付かず 4014 判定が無言で消える（time-claims.ts）。
  if (!Object.hasOwn(claims, 'iat')) {
    // 非有限・負値・文字列の `iat` は 4014 判定を無効化する。
    const now = nowSeconds ?? Math.floor(Date.now() / 1000);
    payload.iat = assertEpochSeconds(now, ErrorCodes.SIG_INVALID);
  }
  if (issuer !== undefined) {
    payload.iss = issuer;
  }
  if (cnf !== undefined) {
    payload.cnf = cnf;
  }
  if (status !== undefined) {
    payload.status = status;
  }

  const header = buildJwsHeader(signer, resolveIssuanceTyp(ownProperty<SdJwtVcTyp>(opts, 'typ')));
  const headerSeg = base64urlText(JSON.stringify(header));
  // payload の直列化は 1 回だけ行い、同じ文字列を「署名対象の base64url」と「Art.9 走査対象」の
  // 両方に使う。走査した値と署名バイト列が定義上一致するため、検査後に payload を読み直す余地が
  // ない（発行時のガード。詳細は `gdpr-guard.ts`）。署名前に走るので fail-closed。
  const payloadJson = JSON.stringify(payload);
  const encodedDisclosures = disclosures.map((d) => d.encoded);
  assertNoSpecialCategoryInSdJwtIssuance(payloadJson, encodedDisclosures);
  return {
    signingInput: `${headerSeg}.${base64urlText(payloadJson)}`,
    disclosureParts: encodedDisclosures.join('~'),
  };
}

/**
 * signing-input・署名・Disclosure 群から SD-JWT 文字列を組み立てる（末尾 `~` 終端）。
 *
 * @param parts signing-input と `~` 連結済み Disclosure 群。
 * @param signature Issuer-signed JWT の 64 バイト raw 署名。
 * @returns SD-JWT 文字列（`<issuerJwt>~<d1>~...~<dN>~`）。
 */
function assembleSdJwt(parts: SdJwtIssuanceParts, signature: Uint8Array): string {
  const issuerJwt = `${parts.signingInput}.${base64urlnopad.encode(signature)}`;
  return parts.disclosureParts.length > 0
    ? `${issuerJwt}~${parts.disclosureParts}~`
    : `${issuerJwt}~`;
}

/**
 * SD-JWT VC を発行する。
 *
 * `disclosureClaims` に指定されたクレームを Disclosure へ分離し、その digest を payload の
 * `_sd` 配列に格納する。残りのクレームと `vct` / `cnf` / `status` / `iss` は平文 payload に残す。
 * `iat`（発行時刻）は既定で付与する（`opts.nowSeconds` で注入可能。`claims` の明示指定が優先）。
 * `iat` / `exp` / `nbf` / `iss` / `vct` / `cnf` / `status` は `disclosureClaims` に指定しても
 * Disclosure へは回さず平文 payload に残す（`NON_DISCLOSABLE_CLAIMS`。隠すと期限切れ判定 3024 /
 * 未発効判定 3025 / 未来 `iat` 判定 4014 を素通りできるため —）。
 * Issuer-signed JWT を `signer` で署名し、`~` 区切りで Disclosure を連結して返す（末尾 `~`）。
 *
 * `disclosureClaims` のうち `claims` に存在しないクレーム名は単に無視する（Disclosure・`_sd`
 * のいずれにも反映しない）。開示対象の厳格な存在検証（`3014` 相当）は本実装のスコープ外。
 *
 * @param signer Issuer の JWT-VC 署名鍵（`CredentialSigner`）。
 * @param opts vct / 開示クレーム / 平文クレーム / cnf / status 等。
 * @returns SD-JWT 文字列（`<issuerJwt>~<d1>~...~<dN>~`）。
 * @throws 受理対象外の `typ` を指定した場合（`3002`）／平文クレーム・開示クレームが Art.9
 *         特別カテゴリ属性を含む場合（`10607`）。署名演算失敗時は signer 側で `1020`。
 */
export function createSdJwt(signer: CredentialSigner, opts: CreateSdJwtOptions): string {
  const parts = buildSdJwtIssuanceParts(signer, opts);
  const signature = signer.sign(new TextEncoder().encode(parts.signingInput));
  return assembleSdJwt(parts, signature);
}

/**
 * SD-JWT VC を発行する（非同期署名対応版）。
 *
 * Disclosure 生成・payload 組み立ては `createSdJwt` と完全に同一で、署名だけを `await` する。
 * 同期の local signer（`createPrivateKeySigner`）と非同期の Remote Signer
 * （`createRemoteSigner`。KMS / HSM）のどちらも受け付けるため、`AnyCredentialSigner` を取る。
 *
 * @param signer Issuer の JWT-VC 署名鍵（同期 `CredentialSigner` / 非同期 `AsyncCredentialSigner`）。
 * @param opts vct / 開示クレーム / 平文クレーム / cnf / status 等。
 * @returns SD-JWT 文字列（`<issuerJwt>~<d1>~...~<dN>~`）の Promise。
 * @throws 受理対象外の `typ` を指定した場合（`3002`）／平文クレーム・開示クレームが Art.9 特別
 *         カテゴリ属性を含む場合（`10607`）／署名演算・外部署名呼び出しが失敗した場合（`1020`）。
 */
export async function createSdJwtAsync(
  signer: AnyCredentialSigner,
  opts: CreateSdJwtOptions,
): Promise<string> {
  const parts = buildSdJwtIssuanceParts(signer, opts);
  const signature = await signer.sign(new TextEncoder().encode(parts.signingInput));
  return assembleSdJwt(parts, signature);
}

/**
 * SD-JWT 文字列を分解する。
 *
 * `~` で分割し、先頭を Issuer-signed JWT、中間を Disclosure 群とする。末尾要素が空文字列なら
 * KB-JWT なし（末尾 `~` 終端）、非空ならそれを KB-JWT とみなす（draft の終端規約）。
 *
 * @param sdJwt SD-JWT 文字列。
 * @returns Issuer-signed JWT・Disclosure 群・KB-JWT（あれば）。
 * @throws Issuer-signed JWT が欠落している場合や Disclosure が不正な場合（VericertsError、code `3010`）。
 */
export function parseSdJwt(sdJwt: string): SdJwtParts {
  const segments = sdJwt.split('~');
  const issuerJwt = segments[0];
  if (issuerJwt === undefined || issuerJwt.length === 0 || segments.length < 2) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  // 末尾要素は終端マーカー（空文字列）または KB-JWT。
  const last = segments[segments.length - 1] as string;
  const keyBinding = last.length > 0 ? last : undefined;
  // Disclosure は index 1 〜 末尾-1（末尾は KB-JWT or 空終端のため常に除外）。
  const disclosureSegs = segments.slice(1, segments.length - 1);
  const disclosures = disclosureSegs.filter((s) => s.length > 0).map((s) => decodeDisclosure(s));
  return keyBinding !== undefined
    ? { issuerJwt, disclosures, keyBinding }
    : { issuerJwt, disclosures };
}

/**
 * 選択的開示: 指定したクレームの Disclosure だけを残して SD-JWT を再構成する。
 *
 * Issuer-signed JWT はそのまま保持し、`claimsToDisclose` に含まれるクレーム名の Disclosure のみ
 * を連結する。未指定のクレームの Disclosure は除外され、検証側で値を復元できなくなる。
 * KB-JWT は提示時に別途付与するため、本操作では末尾 `~` 終端（KB-JWT なし）で返す。
 *
 * @param sdJwt 元の SD-JWT 文字列。
 * @param claimsToDisclose 開示するクレーム名。
 * @returns 選択された Disclosure のみを含む SD-JWT 文字列（末尾 `~`）。
 */
export function selectDisclosures(sdJwt: string, claimsToDisclose: readonly string[]): string {
  const { issuerJwt, disclosures } = parseSdJwt(sdJwt);
  // 配列要素の Disclosure（`claimName` が `undefined`）は集合に含まれないため選択されない。
  const wanted = new Set<string | undefined>(claimsToDisclose);
  const selected = disclosures.filter((d) => wanted.has(d.claimName)).map((d) => d.encoded);
  return selected.length > 0 ? `${issuerJwt}~${selected.join('~')}~` : `${issuerJwt}~`;
}
