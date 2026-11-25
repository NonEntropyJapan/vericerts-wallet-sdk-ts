/**
 * 分離型 Holder Service 向け KB-JWT テンプレート（署名前）プリミティブ。
 *
 * 分離型 Holder Service 向けに KB-JWT のテンプレートを構築する。
 *
 * ## 目的
 *
 * 既存の `addKeyBinding`（`verify.ts`）は「VC バイト列」と「Holder 秘密鍵」の両方を 1 プロセスで
 * 持つ人間ウォレット向けの API である。Agent を Holder とする構成では、次のセキュリティ境界を
 * 引きたい:
 *
 * - Holder Service: VC バイト列を永続化する。**Session 秘密鍵は保持しない。**
 * - Agent Session: 秘密鍵をプロセスメモリ内だけに置き、署名だけを行う。
 *
 * 本モジュールはこの境界に沿って KB-JWT 生成を 2 段に分割する:
 *
 * 1. `createKeyBindingTemplate`: 保管済み SD-JWT VC から開示クレームを絞り、`{ nonce, aud, iat,
 *    sd_hash }` を確定して **署名前の** signing input を返す（秘密鍵を要求しない）。
 * 2. `attachKeyBinding` / `attachKeyBindingSignature`: 外部（Agent Session）で署名された KB-JWT を
 *    受け取り、テンプレートと整合することを検証したうえで SD-JWT presentation に合成する。
 *
 * `addKeyBinding` も本モジュールのコアに委譲するため、統合構成と分離構成で生成される KB-JWT の
 * バイト列は同一になる（両者が食い違う余地を構造的に無くす）。
 *
 * ## nonce / audience / sd_hash の取り違え防止
 *
 * - `sd_hash` は**呼び出し側から受け取らない**。常に提示部から SDK が計算する（引数の取り違えが
 *   起こり得ない）。
 * - `nonce` / `audience` は位置引数ではなく名前付きフィールド（`KeyBindingOptions`）で受け取り、
 *   空文字列を拒否する（同型の `string` 同士の入れ替えを実行時に検出する）。
 * - 合成時（`attachKeyBinding`）に、署名済み KB-JWT の header / payload セグメントが
 *   `template.signingInput` と**バイト単位で一致**することを検証し、さらに `sd_hash` を提示部から
 *   再計算して突き合わせる。テンプレート発行後に提示部が差し替えられた場合・別リクエスト向けの
 *   KB-JWT が流用された場合・署名対象に余剰クレームが混入された場合はここで落ちる。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に salt・開示値・JWT・nonce を含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { base64urlText } from '../../base64url.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { isEpochSeconds } from '../../primitives/option-guard.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import {
  type CredentialAlg,
  decodeCompactJwsOrThrow,
  SUPPORTED_CREDENTIAL_ALGS,
  verifyWithJwk,
} from '../vc/jws.js';
import { buildJwsHeader } from '../vc/signer.js';
import { validateCnf } from './claims.js';
import { parseSdJwt, selectDisclosures } from './sdjwt.js';

/** KB-JWT の `typ`（draft-ietf-oauth-selective-disclosure-jwt）。 */
export const KB_JWT_TYP = 'kb+jwt' as const;

/** SD-JWT の KB-JWT を除いた提示部（`<issuerJwt>~<d1>~...~<dN>~`）の sd_hash（base64url）を計算する。 */
export function computeSdHash(sdJwtWithoutKb: string): string {
  return base64urlnopad.encode(sha256(new TextEncoder().encode(sdJwtWithoutKb)));
}

/** `addKeyBinding` / `createKeyBindingTemplate` の共通入力。 */
export interface KeyBindingOptions {
  /** Verifier 発行の nonce。 */
  readonly nonce: string;
  /** Verifier 識別子（audience / client_id）。 */
  readonly audience: string;
  /** 発行時刻（エポック秒）。既定は現在時刻。テストの決定性のため注入可能。 */
  readonly iatSeconds?: number;
}

/** KB-JWT のヘッダ。 */
export interface KeyBindingHeader {
  /** 署名アルゴリズム（Agent Session 鍵の alg）。 */
  readonly alg: CredentialAlg;
  /**
   * 署名鍵の鍵 ID（`kid`）。未指定ならプロパティ自体を出力しない。
   *
   * Holder が複数鍵を持つ構成（KMS / HSM 等）で、Verifier が `cnf` の他に検証鍵を特定する手掛かり
   * として用いる。キー順は `alg` → `kid` → `typ`。
   */
  readonly kid?: string;
  /** 常に `kb+jwt`。 */
  readonly typ: typeof KB_JWT_TYP;
}

/**
 * KB-JWT のペイロード。
 *
 * フィールド名は KB-JWT のワイヤ表現（snake_case）に合わせる。`sd_hash` は SDK が提示部から計算する
 * ため、呼び出し側が組み立てることはない。
 */
export interface KeyBindingPayload {
  /** Verifier 発行の nonce（リプレイ防止）。 */
  readonly nonce: string;
  /** Verifier 識別子（OID4VP の `client_id`）。 */
  readonly aud: string;
  /** 発行時刻（エポック秒）。 */
  readonly iat: number;
  /** KB-JWT を除いた提示部の SHA-256（base64url）。 */
  readonly sd_hash: string;
}

/**
 * 秘密鍵なしで生成できる KB-JWT の署名前テンプレート。
 *
 * Holder Service はこれを返すだけでよく、Agent Session は `signingInput` の UTF-8 バイト列に
 * 署名して KB-JWT を完成させる。
 */
export interface KeyBindingTemplate {
  /** KB-JWT を付与する前の提示部 SD-JWT（開示クレーム適用済み、末尾 `~`）。 */
  readonly presentation: string;
  /** KB-JWT ヘッダ。 */
  readonly header: KeyBindingHeader;
  /** KB-JWT ペイロード。 */
  readonly payload: KeyBindingPayload;
  /**
   * 署名対象文字列（`base64url(header).base64url(payload)`）。
   *
   * Agent Session はこの文字列の UTF-8 バイト列に署名し、64 バイト raw 署名を返す。
   */
  readonly signingInput: string;
}

/** `createKeyBindingTemplate` の入力。 */
export interface KeyBindingTemplateOptions extends KeyBindingOptions {
  /** KB-JWT に署名する Agent Session 鍵の JWS alg（**秘密鍵は渡さない**）。 */
  readonly alg: CredentialAlg;
  /**
   * KB-JWT ヘッダへ載せる鍵 ID（`kid`）。未指定ならヘッダに `kid` を出力しない。
   *
   * Agent Session 鍵が KMS / HSM 上にある構成では、これが検証側へ鍵を伝える唯一の手段になる。
   */
  readonly kid?: string;
  /**
   * 開示するクレーム名。指定時は `selectDisclosures` で提示部を絞り込む。
   * 未指定の場合は入力 SD-JWT をそのまま提示部として扱う。
   */
  readonly disclosedClaims?: readonly string[];
}

/** `attachKeyBinding` / `attachKeyBindingSignature` の入力。 */
export interface AttachKeyBindingOptions {
  /**
   * 提示部 issuer JWT の `cnf.jwk` で KB-JWT 署名を検証するか。既定 `true`。
   *
   * Holder Service は「Session 鍵で正しく署名されたか」をここで拒否できる。`cnf` を持たない
   * SD-JWT は Key Binding を信頼検証できないため、`true` のときは `3012` で拒否する。
   */
  readonly verifySignature?: boolean;
}

/** nonce / audience が非空文字列であること（空・未設定・非文字列は 3012）を検証する。Transaction Data 版と共有する。 */
export function assertBindingValue(value: unknown): void {
  if (typeof value !== 'string' || value.length === 0) {
    // 値そのものは秘密を含み得るため例外に載せない。
    throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
  }
}

/**
 * 秘密鍵なしで KB-JWT の署名前テンプレートを生成する（分離型 Holder Service 用）。
 *
 * `opts.disclosedClaims` 指定時は `selectDisclosures` で提示部を絞り込んだうえで、その提示部に対する
 * `sd_hash` を計算する。`sd_hash` は呼び出し側から受け取らないため、`nonce` / `audience` との
 * 取り違えは起こり得ない。
 *
 * @param sdJwt 保管済み SD-JWT VC（KB-JWT なし）。
 * @param opts 署名 alg・KB-JWT ヘッダへ載せる `kid`（任意）・nonce・audience・開示クレーム・iat。
 * @returns 署名前テンプレート（`signingInput` に署名して KB-JWT を完成させる）。
 * @throws 入力 SD-JWT に既に KB-JWT が付与されている場合（`3010`）、`nonce` / `audience` が空の場合・
 *         未対応 alg の場合（`3012`）（VericertsError）。
 */
export function createKeyBindingTemplate(
  sdJwt: string,
  opts: KeyBindingTemplateOptions,
): KeyBindingTemplate {
  if (!SUPPORTED_CREDENTIAL_ALGS.has(opts.alg)) {
    throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
  }
  // `nonce` / `audience` は型上必須だが、型の無い JS から渡し忘れるとプロトタイプ鎖の汚染値が
  // 「指定された値」に化け、`assertBindingValue` を素通りして **KB-JWT の署名対象**に載る
  // （Verifier 側のリプレイ対策・aud バインドが攻撃者の選んだ値になる）。
  const nonce = ownProperty<string>(opts, 'nonce') as string;
  const audience = ownProperty<string>(opts, 'audience') as string;
  assertBindingValue(nonce);
  assertBindingValue(audience);

  if (!sdJwt.endsWith('~')) {
    // 既に KB-JWT が付与されている（末尾が `~` でない）入力には再付与しない。`selectDisclosures` は
    // 既存 KB-JWT を捨てて必ず末尾 `~` の文字列を返すため、判定は絞り込み**前**の入力に対して行う。
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  // 継承値を拾うと、開示クレームを指定していない提示でも汚染値が絞り込み条件になり、
  // sd_hash（= KB-JWT の署名対象）が呼び出し側の意図しない提示部に対して計算される。
  const disclosedClaims = ownProperty<readonly string[]>(opts, 'disclosedClaims');
  const iat = ownProperty<number>(opts, 'iatSeconds') ?? Math.floor(Date.now() / 1000);
  // 非有限・負値・文字列の `iat` は署名済み KB-JWT に `null` 等で載り、鮮度判定が成立しない。
  if (!isEpochSeconds(iat)) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  const presentation =
    disclosedClaims === undefined ? sdJwt : selectDisclosures(sdJwt, disclosedClaims);

  // 発行系（`issueCredential` / `createSdJwt`）と同じ組み立てを共有し、`kid` の出力条件と
  // キー順が KB-JWT だけ食い違わないようにする。
  const header: KeyBindingHeader = buildJwsHeader(opts, KB_JWT_TYP);
  const payload: KeyBindingPayload = {
    nonce,
    aud: audience,
    iat,
    sd_hash: computeSdHash(presentation),
  };
  const signingInput = `${base64urlText(JSON.stringify(header))}.${base64urlText(
    JSON.stringify(payload),
  )}`;
  return { presentation, header, payload, signingInput };
}

/** 提示部 issuer JWT から `cnf` を取り出す（KB 検証必須なので不正形状は 3012）。 */
function extractCnfJwk(presentation: string): ReturnType<typeof validateCnf> {
  const parts = parseSdJwt(presentation);
  // Issuer-signed JWT の構造不正は KB 合成不能として正規化する（入力は漏らさない）。
  const issuerPayload = decodeCompactJwsOrThrow(parts.issuerJwt, ErrorCodes.SIG_INVALID).payload;
  // `issuerPayload` はパース境界（`parse-json.ts`）を通るため**入れ子まで `null` プロトタイプ**で、
  // `Object.prototype.cnf` の汚染は現状届かない。own 限定読みはそれと**重畳する多層防御**で、鎖読みへ戻すと**`cnf` を持たない SD-JWT
  // でも汚染値が Holder バインド鍵として採用され攻撃者鍵の KB-JWT が連結される**（`attachKeyBinding`
  // が `verifySignature` の汚染に対して守る不変条件がここで破れる）。
  return validateCnf(ownProperty<unknown>(issuerPayload, 'cnf'), true);
}

/**
 * 外部（Agent Session）で署名された KB-JWT を SD-JWT presentation に合成する。
 *
 * テンプレートとの整合を全面的に検証してから連結するため、Holder Service は「別リクエスト向けの
 * KB-JWT の流用」「テンプレート発行後に提示部が差し替えられた合成」「署名対象への余剰クレーム混入」
 * 「別鍵での署名」を拒否できる。
 *
 * 検証内容:
 * 1. KB-JWT が 3 セグメントのコンパクト JWS としてデコードできること。
 * 2. header / payload セグメントが `template.signingInput` とバイト単位で完全一致すること
 *    （`typ` / `alg` / `nonce` / `aud` / `iat` / `sd_hash` の一致に加え、余剰クレームや
 *    別シリアライズの混入もここで落ちる）。
 * 3. `template.payload.sd_hash` が `template.presentation` から再計算した値と一致すること。
 * 4. `opts.verifySignature !== false` の場合、提示部の `cnf.jwk` で署名検証に成功すること。
 *
 * @param template `createKeyBindingTemplate` が返したテンプレート。
 * @param keyBindingJwt 外部署名済みの KB-JWT（`header.payload.signature`）。
 * @param opts 署名検証の有無。
 * @returns KB-JWT を連結した SD-JWT presentation。
 * @throws 構造不正（`3010`）/ テンプレート不一致・`sd_hash` 不一致・署名不一致・`cnf` 不在・
 *         `cnf.jwk` の曲線が `alg` と不一致（`3012`）の場合（VericertsError）。
 */
export function attachKeyBinding(
  template: KeyBindingTemplate,
  keyBindingJwt: string,
  opts: AttachKeyBindingOptions = {},
): string {
  // KB-JWT の構造不正。入力は漏らさず SD-JWT 失敗面へ正規化する。
  const decoded = decodeCompactJwsOrThrow(keyBindingJwt, ErrorCodes.SIG_INVALID);

  // 署名対象（header / payload セグメント）がテンプレートと**バイト単位で**一致すること。
  // `decodeCompactJws` はセグメントがちょうど 3 であることを保証し、`signingInput` は base64url なので
  // `.` を含まない。よって前方一致だけで完全一致が保証される。既知フィールドの照合と違い、余剰クレーム
  // （`exp` / `transaction_data_hashes` 等）やテンプレート未宣言の `kid`、別シリアライズもここで落ちる。
  if (!keyBindingJwt.startsWith(`${template.signingInput}.`)) {
    throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
  }

  // テンプレート発行後に提示部が差し替えられていないことを、再計算した sd_hash で確認する
  // （テンプレート自体の改竄検出。signingInput 一致だけでは提示部の差し替えを検出できない）。
  if (template.payload.sd_hash !== computeSdHash(template.presentation)) {
    throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
  }

  // `opts.verifySignature !== false` はプロトタイプ鎖を辿る。`Object.prototype.verifySignature
  // = false` の汚染下では **既定（検証あり）の呼び出しでも署名検証がまるごとスキップされ、
  // cnf の鍵で署名されていない KB-JWT が連結される**。
  const verifySignature = ownProperty<boolean>(opts, 'verifySignature');
  if (verifySignature !== false) {
    const cnf = extractCnfJwk(template.presentation);
    if (cnf === undefined) {
      // cnf が無ければ KB-JWT を信頼検証できない（`verifySdJwt` と同じ判断）。
      throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
    }
    let verified: boolean;
    try {
      // `verifyWithJwk` は digest ではなく signing-input を受け取る（`EdDSA` は PureEdDSA のため
      // 事前ハッシュした digest では検証できない）。`decoded` をそのまま渡す。
      verified = verifyWithJwk(template.header.alg, decoded, cnf.jwk);
    } catch {
      // `cnf.jwk` の曲線が alg と不一致な場合など、鍵変換由来の例外（`2001`）を契約内へ正規化する。
      // cause は渡さない（例外に秘密を載せない方針）。
      throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
    }
    if (!verified) {
      throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
    }
  }

  return `${template.presentation}${keyBindingJwt}`;
}

/**
 * 外部で生成した raw 署名から KB-JWT を組み立て、SD-JWT presentation に合成する。
 *
 * Agent Session が `template.signingInput` の UTF-8 バイト列に署名して返した 64 バイト raw 署名を
 * そのまま渡せる（KB-JWT のコンパクト表現を Agent 側で組み立てる必要が無い）。検証内容は
 * `attachKeyBinding` と同じ。
 *
 * @param template `createKeyBindingTemplate` が返したテンプレート。
 * @param signature `template.signingInput` に対する 64 バイト raw 署名（`r || s`）。
 * @param opts 署名検証の有無。
 * @returns KB-JWT を連結した SD-JWT presentation。
 * @throws `attachKeyBinding` と同じ（VericertsError）。
 */
export function attachKeyBindingSignature(
  template: KeyBindingTemplate,
  signature: Uint8Array,
  opts: AttachKeyBindingOptions = {},
): string {
  const keyBindingJwt = `${template.signingInput}.${base64urlnopad.encode(signature)}`;
  return attachKeyBinding(template, keyBindingJwt, opts);
}
