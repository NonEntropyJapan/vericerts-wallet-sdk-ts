/**
 * OID4VP リクエストに応じて VP を作成し、JWT-VP として署名する。
 *
 * VC 選択は呼び出し側が行う。本モジュールは要求解析済みの
 * `PresentationRequest` に対して `matchCredentialsAgainstRequest`（`match-credentials.ts`）を
 * 再利用し、呼び出し側が選んだ VC（`vcIDs` から解決済み）が要求の候補集合に含まれることだけを
 * 検証する。DCQL の `credential_sets` / PEx v2 の `submission_requirements` のような複数 VC の
 * 組み合わせを満たす VC の最終選択は呼び出し側が行う。
 *
 * `parsePresentationRequest`（`request_uri` 参照形式では HTTP 取得 + JAR 署名検証を伴う）は本関数の
 * 外側で 1 回だけ呼ぶ（呼び出し側の `wallet/credential/create-presentation.ts` が担う）。VC 選択の
 * 検証にも VP の `audience` / `nonce` の抽出にも同じ解析結果を使うことで、要求解析の二重実行
 * （通信・暗号検証の二重コスト）を避ける。
 *
 * VP 構築・署名は既存プリミティブ（`credential/presentation/issue.ts` の `issuePresentationAsync`）を
 * 呼ぶだけで、新しい署名アルゴリズム・VP 暗号構造は発明しない。
 *
 * Wallet ローカル VC ストア（`CredentialStore`）は構造化済み `VerifiableCredential`（JSON-LD 相当）
 * のみを保持するため、既定では `verifiableCredential` に選択 VC を object（JSON-LD VC）表現のまま
 * 埋め込む。ただし JWT-VC は発行者署名が
 * JWS 側にしか無く、`vc` クレームだけを object に潰すと署名が VP から失われ、`verifyPresentation` が
 * 内包 VC を `valid: false`（3002）にする。原本のコンパクト JWS を持つ呼び出し側は
 * `opts.rawCredentials`（`vc.id` → JWT-VC 文字列）で渡すと、該当 VC は W3C VCDM 1.1 の
 * `verifiableCredential: ["<JWT>"]` 形で載る。含まれる各 VC の署名検証は本関数の責務外
 * （VP 全体の検証は `verifyPresentation`、内包 VC の検証は呼び出し側が `verifyCredential` で行う）。
 *
 * LoA（Level of Assurance）判定は本モジュールでは判定ロジックを持たない。VC 選択の検証後・VP 構築前に
 * `opts.checkLoa` を呼び出すフック位置だけを用意し（未指定時は no-op）、実際の判定（`requiredLoA` の
 * 読み取り・`evidence-tou/evidence.ts` の `verifyEvidence` 呼び出し・`LOA_MISMATCH`(10030) の送出）は
 * 呼び出し側の `wallet/credential/create-presentation.ts`が `checkLoa` として注入する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に VC 本文・クレーム値・Request 本文を含めない。
 */

import { issuePresentationAsync } from '../../credential/presentation/issue.js';
import type { VerifiablePresentation } from '../../credential/presentation/vp.js';
import { VC_V2_CONTEXT, VP_TYPE } from '../../credential/presentation/vp.js';
import type { CredentialSignerAlg } from '../../credential/vc/jws.js';
import type { CredentialSigner } from '../../credential/vc/signer.js';
import type { VerifiableCredential } from '../../credential/vc/vc.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { matchCredentialsAgainstRequest } from '../match-credentials/index.js';
import type { PresentationRequest } from '../request.js';

/**
 * Art.16 訂正権フォールバック（`markCredentialDisputed`）に伴う VP メタデータ。
 *
 * VP 本体の署名対象ではなく、呼び出し側（Wallet ファサード）が `CredentialRecord.disputed` から
 * 算出して `CreatedPresentation` に付与する（`internal/auth/create-presentation/index.ts` の
 * `createPresentation` は GDPR ドメインの `CredentialRecord` を知らないレイヤーのため、本体では
 * 算出しない。`wallet/credential/create-presentation.ts` 参照）。
 */
export interface PresentationMetadata {
  /** 提示 VC のいずれかが訂正要求中（`markCredentialDisputed` 済み）の場合に `true`。 */
  readonly disputed: boolean;
}

/** `createPresentation` が返す署名済み VP（VP 構造 + JWT-VP 文字列）。 */
export interface CreatedPresentation extends VerifiablePresentation {
  /** 署名済み JWT-VP（コンパクト JWS）。 */
  readonly jwt: string;
  /**
   * 提示 VC のいずれかが訂正要求中の場合に付与するメタデータ。UI 警告表示は
   * 呼び出し側（extension 等）の責務であり、SDK はここに情報を含めるところまでを担う。
   */
  readonly presentationMetadata?: PresentationMetadata;
}

/**
 * VC 選択後・VP 構築前に差し込む LoA（Level of Assurance）判定フック。
 *
 * 本モジュールは判定ロジックを持たず呼び出しフック位置だけを提供する（未指定なら no-op）。
 * 判定の実体（`requiredLoA` の読み取り・`verifyEvidence` の呼び出し）は呼び出し側
 * （`wallet/credential/create-presentation.ts` の `buildLoaCheck`）が注入する。要件を満たさないと
 * 判定した場合は `VericertsError(ErrorCodes.LOA_MISMATCH)`（10030）を throw する。
 *
 * @param selectedVCs 提示のために選択された（要求の候補集合に含まれることを確認済みの）VC。
 */
export type LoaCheck = (selectedVCs: readonly VerifiableCredential[]) => void | Promise<void>;

/** `createPresentation` のオプション（VP 署名鍵は呼び出し側が解決して渡す）。 */
export interface CreatePresentationOptions {
  /** VC 選択後・VP 構築前の LoA 判定フック。未指定なら判定をスキップする。 */
  readonly checkLoa?: LoaCheck;
  /**
   * `vc.id` → 署名済み JWT-VC（コンパクト JWS）。載っている VC は object ではなく**生の JWS 文字列**で
   * VP に内包する（発行者署名を VP に残す）。呼び出し側が選択 VC と同じ原本から作った対応づけを
   * 渡すこと（SDK は `vc.id` の一致だけを見る）。値が文字列でなければ `3002` で拒否する。
   */
  readonly rawCredentials?: ReadonlyMap<string, string>;
}

/**
 * 選択 VC を VP の `verifiableCredential` 要素にする。`opts.rawCredentials` に原本の JWT-VC があれば
 * 生のコンパクト JWS 文字列で（発行者署名を残す）、無ければ object のまま載せる。
 *
 * `rawCredentials` は own 限定で読む（継承値だと汚染された対応づけが署名対象になる）。`Map` 以外・
 * 文字列以外の値は黙って object 表現へ落とさず `3002` で拒否する（署名の無い VC を VP に載せない）。
 */
function embedCredentials(
  selectedVCs: readonly VerifiableCredential[],
  opts: CreatePresentationOptions | undefined,
): VerifiablePresentation['verifiableCredential'] {
  const raw = opts === undefined ? undefined : ownProperty<unknown>(opts, 'rawCredentials');
  if (raw !== undefined && !(raw instanceof Map)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return selectedVCs.map((vc) => {
    const id = ownProperty<string>(vc, 'id');
    const jws = raw === undefined || id === undefined ? undefined : raw.get(id);
    if (jws === undefined) {
      // `VerifiableCredential` interface に index signature が無いため直接は代入できない。実体は
      // JSON-LD object であり値の変換は伴わない。
      return vc as unknown as Readonly<Record<string, unknown>>;
    }
    if (typeof jws !== 'string' || jws.length === 0) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    return jws;
  });
}

/**
 * OID4VP リクエストに応じて VP を作成し、JWT-VP として署名する。
 *
 * 手順:
 * 1. `selectedVCs` が空、または要求の候補集合（`matchCredentialsAgainstRequest` の結果）が空
 *    （`dcql_query` / `presentation_definition` のいずれも無い要求を含む）の場合は
 *    `VC_REQUIREMENT_MISMATCH`（3080）で拒否する。空の `vcIDs` をそのまま署名まで進めると、
 *    VC を含まない VP にペルソナ鍵で署名してしまうため。
 * 2. 選択 VC（`selectedVCs`）が要求の候補集合に含まれることを検証する（own `id` の一致のみで判定。
 *    `heldCredentials` に対して評価する）。含まれない VC が 1 件でもあれば同じく `VC_REQUIREMENT_MISMATCH`
 *    （3080）で拒否する。
 * 3. LoA 判定フック（`opts.checkLoa`）を呼ぶ（未指定なら no-op。判定を行う場合は
 *    `LOA_MISMATCH`（10030）を throw し得る）。
 * 4. VP を構築する（`holder` = `holderDid`、`verifiableCredential` = 選択 VC。`opts.rawCredentials` に
 *    原本の JWT-VC がある VC は生の JWS 文字列、それ以外は object 表現のまま）。
 * 5. `issuePresentationAsync` で JWT-VP として署名する（`audience` = `request.clientId`、
 *    `nonce` = `request.nonce`。いずれも own プロパティとして読み、どちらかが `undefined`
 *    （own プロパティとして存在しない）なら署名せず `OID4VP_REQUEST_PARSE_FAILED`（8030）で
 *    拒否する。aud/nonce の無いリプレイ可能な VP を作らないための fail-closed）。
 *
 * @param request 解析済みの Presentation Request（呼び出し側が `parsePresentationRequest` で解析済み）。
 * @param selectedVCs 提示する VC（呼び出し側が `vcIDs` から解決済み）。1 件以上必須。
 * @param heldCredentials 要件合致検証の母集団（処理制限中の VC を除外済みの保有 VC 全件）。
 * @param signer holder の VP 署名鍵（`kid` 付き。DID は `holderDid` と対応していること）。
 * @param holderDid 提示者 DID（VP の `holder` / JWT-VP の `iss`）。
 * @param opts LoA 判定フック。
 * @returns 署名済み VP（`jwt` に JWT-VP、他メンバは VP 構造）。
 * @throws `selectedVCs` が空の場合、要求の候補集合が空の場合、選択 VC が要求の候補集合に含まれない
 *         場合（いずれも `VC_REQUIREMENT_MISMATCH`、code `3080`）、`presentation_definition` の
 *         構造不正、`request` が own プロパティとして `clientId` / `nonce` を持たない場合（いずれも
 *         `OID4VP_REQUEST_PARSE_FAILED`、code `8030`）、`dcql_query` の要求 format が SDK 未対応の
 *         場合（`FORMAT_NEGOTIATION_FAILED`、code `8050`）、署名演算が失敗した場合（code `1020`）、
 *         `opts.checkLoa` が指定されている場合はその判定結果（呼び出し側が注入する検証。
 *         `wallet/credential/create-presentation.ts` の実装では `LOA_MISMATCH`、code `10030`）
 *         （VericertsError）。
 */
export async function createPresentation(
  request: PresentationRequest,
  selectedVCs: readonly VerifiableCredential[],
  heldCredentials: readonly VerifiableCredential[],
  signer: CredentialSigner<CredentialSignerAlg>,
  holderDid: string,
  opts?: CreatePresentationOptions,
): Promise<CreatedPresentation> {
  // 空の `selectedVCs` を拒否せずに VP 構築へ進めると、`createPresentation(uri, [])` が
  // 「VC を 1 件も含まない署名済み JWT-VP」（`iss` = ペルソナ DID、`aud`/`nonce` = 検証者が指定した
  // 任意値）に署名してしまう。候補集合が空の場合も
  // 同様に、検証しようのない VP を組み立てて署名してしまわないよう先に拒否する。
  if (selectedVCs.length === 0) {
    throw new VericertsError(ErrorCodes.VC_REQUIREMENT_MISMATCH);
  }
  const candidates = await matchCredentialsAgainstRequest(request, heldCredentials);
  if (candidates.length === 0) {
    throw new VericertsError(ErrorCodes.VC_REQUIREMENT_MISMATCH);
  }
  // 候補 VC の `id` は自身のプロパティに限って読む（`oid4vp.ts` の
  // `buildVPTokenEntry` と同じ扱い）。プロトタイプ鎖読みだと `Object.prototype.id` 汚染で
  // own `id` を持たない VC が `candidateIds` に紛れ込み、`selectedVCs` 側の判定で
  // 「要求に合致しない VC」が開示制御をバイパスして候補扱いされる。
  const candidateIds = new Set<string>();
  for (const vc of candidates) {
    const id = ownProperty<string>(vc, 'id');
    if (id !== undefined) {
      candidateIds.add(id);
    }
  }
  for (const vc of selectedVCs) {
    const id = ownProperty<string>(vc, 'id');
    if (id === undefined || !candidateIds.has(id)) {
      throw new VericertsError(ErrorCodes.VC_REQUIREMENT_MISMATCH);
    }
  }

  // `opts.checkLoa` は関数値（DI フック）のため own 限定ではなく `nonObjectPrototypeProperty` で
  // 読む。own 限定だと正当なクラスインスタンス実装（プロトタイプメソッド）を「未指定」と誤判定する
  // 一方、鎖読みのままだと `Object.prototype.checkLoa` 汚染で `opts={}` でも継承関数が実行され、
  //  LoA ゲート用フックが未指定でも発火してしまう（own-property.ts の使い分け規約）。
  const checkLoa =
    opts === undefined ? undefined : nonObjectPrototypeProperty<LoaCheck>(opts, 'checkLoa');
  await checkLoa?.(selectedVCs);

  const vp: VerifiablePresentation = {
    '@context': [VC_V2_CONTEXT],
    type: [VP_TYPE],
    holder: holderDid,
    verifiableCredential: embedCredentials(selectedVCs, opts),
  };
  // `request` は Verifier 由来のデータであり、`clientId` / `nonce` は**署名済み JWT-VP** の
  // `aud` / `nonce` にそのまま載る。鎖読みだと `Object.prototype.clientId` / `nonce` 汚染で、
  // それらを持たない要求でも攻撃者が選んだ値が audience バインド・リプレイ防止 nonce として
  // 署名されてしまう（`oid4vp.ts` の `buildVPTokenEntry` と同じ理由）。
  //
  // 読み取った値は検証せずに `as` でキャストしない（own-property.ts が明示的に禁じる）。
  // `clientId` / `nonce` のどちらかが own プロパティとして存在しない場合、キャストで
  // `undefined` 混入を型検査から隠すと aud/nonce の無いリプレイ可能な VP をそのまま
  // 署名してしまう（fail-open）。ここで fail-closed に 8030 で拒否する。
  const clientId = ownProperty<string>(request, 'clientId');
  const nonce = ownProperty<string>(request, 'nonce');
  if (clientId === undefined || nonce === undefined) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  const jwt = await issuePresentationAsync(vp, signer, {
    audience: clientId,
    nonce,
  });
  return { ...vp, jwt };
}
