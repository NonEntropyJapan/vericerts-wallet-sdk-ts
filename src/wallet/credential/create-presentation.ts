/**
 * Wallet ファサードの `createPresentation` の実装。
 *
 * `match.ts` と同じ「`ops.ts` から分離した独立ファイル」パターンで、`CredentialStore` を唯一保持する
 * `GdprFacade` から呼ばれる。VC 選択の検証（要求の候補集合に含まれるか）と VP 構築・署名は内部
 * ファサード `internal/auth/create-presentation/index.ts` の `createPresentation` へ委譲し、本ファイルが
 * 足すのは次の 3 つだけ:
 *
 * 1. `vcIDs` を `CredentialStore` から解決する（未存在は `VC_NOT_FOUND`(3070)。重複は排除する）。
 * 2. holder 署名鍵・DID をアクティブペルソナから解決する（`resolveActiveOwnDidHolder`）。呼び出し側は keyID を指定しない。
 * 3. 解決した VC のいずれかが `markCredentialDisputed` 済み（`CredentialRecord.disputed`）なら、
 *    `CreatedPresentation.presentationMetadata.disputed` に反映する（GDPR Art.16 訂正権フォールバック）。
 *    GDPR ドメインの `CredentialRecord` を知るのは本ファイルのレイヤーだけ
 *    のため、内部ファサード側では算出しない。
 *
 * `parsePresentationRequest`（`request_uri` 参照形式では HTTP 取得 + JAR 署名検証を伴う）は本ファイルで
 * 1 回だけ呼ぶ。解析結果は VC 選択の検証（内部 `createPresentation` 内の `matchCredentialsAgainstRequest`）
 * と VP の `audience` / `nonce` 抽出の両方に使い回すため、要求解析を二重に走らせない
 * （`internal/auth/create-presentation/index.ts` の冒頭コメント参照）。
 */

import {
  type CreatedPresentation,
  createPresentation as createPresentationImpl,
  type LoaCheck,
} from '../../internal/auth/create-presentation/index.js';
import type { PresentationRequest, PresentationRequestOptions } from '../../internal/auth/index.js';
import { parsePresentationRequest } from '../../internal/auth/index.js';
import { isLoA } from '../../internal/credential/evidence-tou/evidence.js';
import type { VerifiableCredential } from '../../internal/credential/index.js';
import { verifyEvidence } from '../../internal/credential/index.js';
import { ErrorCodes, VericertsError } from '../../internal/errors.js';
import type { CredentialStore } from '../../internal/gdpr/index.js';
import type { KeyManager } from '../../internal/keymanager/keymanager.js';
import type { PersonaManager } from '../../internal/persona/persona.js';
import { ownProperty } from '../../internal/prototype-safety/own-property.js';
import { type ActiveSignerOptions, resolveActiveOwnDidHolder } from '../setup.js';

/**
 * `request.requiredLoA` が指定されている場合のみ、内部 `createPresentation`の
 * `opts.checkLoa` フックへ渡す LoA 判定関数を構築する。
 *
 * `requiredLoA` は own-property 経由で読む（`request` は Verifier 由来のパース結果であり、
 * `internal/auth/create-presentation/index.ts` が同じ `request` の `clientId` / `nonce` を
 * `ownProperty` で読んでいるのと同じ多層防御方針。でプロトタイプ汚染による
 * ゲート迂回が複数回見つかっている領域のため、鎖読みに戻さない）。
 *
 * 判定ロジックは新規に実装せず、`evidence-tou/evidence.ts` の `verifyEvidence`
 * （`interpretEvidence` を内包）をそのまま呼ぶ。選択 VC の**全件**が要求 LoA を満たすことを要求し、
 * 1 件でも `sufficient: false` なら `LOA_MISMATCH`（10030）を投げる（fail-safe: 一部の VC だけ
 * 高 LoA でも、低 LoA の VC が紛れ込んだ VP をそのまま提示させない）。
 *
 * 例外の `context` に VC 本文・evidence の値・`verifyEvidence` の `reason` を含めない
 * （`reason` は evidence の解釈結果に由来し得るため）。
 *
 * own 読みした値は `PresentationRequest['requiredLoA']` へ無検証でキャストせず `isLoA` で検証する
 * （own-property.ts の注意。`parsePresentationRequest` 側は既に検証済みだが、`request` は呼び出し側が
 * 直接組み立てたオブジェクトでも渡り得るため、本関数単体でも fail-closed を保つ）。
 */
function buildLoaCheck(request: PresentationRequest): LoaCheck | undefined {
  const requiredLoARaw = ownProperty<unknown>(request, 'requiredLoA');
  if (requiredLoARaw === undefined) {
    return undefined;
  }
  if (!isLoA(requiredLoARaw)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'invalid_required_loa' },
    });
  }
  const requiredLoA = requiredLoARaw;
  return async (selectedVCs) => {
    for (const vc of selectedVCs) {
      const result = await verifyEvidence(vc, requiredLoA);
      if (!result.sufficient) {
        throw new VericertsError(ErrorCodes.LOA_MISMATCH);
      }
    }
  };
}

/** `resolveSelectedCredentials` の解決結果。 */
interface ResolvedSelectedCredentials {
  /** 解決済みの VC 本体（重複排除済み）。 */
  readonly credentials: VerifiableCredential[];
  /** 解決した VC のいずれかが訂正要求中（`markCredentialDisputed` 済み）なら `true`。 */
  readonly disputed: boolean;
}

/**
 * `vcIDs` を `CredentialStore` から解決する。
 *
 * 重複した `vcID` は先頭の 1 件だけを解決する（`[a, a]` のような呼び出しでも同じ VC が VP の
 * `verifiableCredential` に二重埋め込みされないようにする。呼び出し側の書き間違いを想定した
 * 実用上の緩和であり、拒否ではなく重複排除で対応する）。
 *
 * 解決した `CredentialRecord` のいずれかが `disputed` フラグを持つ場合、その旨も併せて返す
 * （呼び出し元が `CreatedPresentation.presentationMetadata` へ反映する）。
 *
 * @throws 指定 VC が 1 件でも見つからない場合（VericertsError、code `3070`）。
 */
async function resolveSelectedCredentials(
  credentials: CredentialStore,
  vcIDs: readonly string[],
): Promise<ResolvedSelectedCredentials> {
  const uniqueVcIds = [...new Set(vcIDs)];
  const selected: VerifiableCredential[] = [];
  let disputed = false;
  for (const vcId of uniqueVcIds) {
    const record = await credentials.get(vcId);
    if (record === null) {
      throw new VericertsError(ErrorCodes.VC_NOT_FOUND);
    }
    selected.push(record.credential);
    if (ownProperty<boolean>(record, 'disputed') === true) {
      disputed = true;
    }
  }
  return { credentials: selected, disputed };
}

/**
 * OID4VP リクエストに応じて VP を作成し、JWT-VP として署名する。
 *
 * @param credentials VC レコードストア（`vcIDs` の解決・要件合致検証の母集団取得に使う）。
 * @param personas ペルソナ管理委譲先（holder 署名鍵・DID の解決）。
 * @param keymanager 鍵管理委譲先（holder 署名鍵の解決）。
 * @param requestURI OID4VP Authorization Request URI（直接形式・`request_uri` 参照形式どちらも可）。
 * @param vcIDs 提示する VC の ID 配列（`CredentialStore` に保存済みの `vc.id`）。
 * @param opts `request_uri` 参照形式でのみ使う Trust Anchor・HTTP 差し替えシーム。
 * @param signing 取り込んだ DID のペルソナで署名するための Resolver・外部秘密鍵の提供元（`resolveActiveHolder`）。
 * @returns 署名済み VP（`jwt` に JWT-VP、他メンバは VP 構造）。
 * @throws アクティブペルソナ未設定（code `2005`）、指定 VC が見つからない場合（`VC_NOT_FOUND`、
 *         code `3070`）、要求解析失敗（code `8030`。`request_uri` 参照形式では取得失敗・署名検証
 *         失敗・`opts.trustAnchors` 未指定に加え、`required_loa` を告知していながら
 *         `low`/`substantial`/`high` のいずれでもない値の場合も含む）、選択 VC が要求の候補集合に
 *         含まれない場合（`VC_REQUIREMENT_MISMATCH`、code `3080`）、`dcql_query` の要求 format が
 *         SDK 未対応の場合（`FORMAT_NEGOTIATION_FAILED`、code `8050`）、要求が `requiredLoA` を持ち
 *         選択 VC のいずれかの evidence エントリが `type` を欠く場合（`VC_SCHEMA_INVALID`、
 *         code `3002`、`verifyEvidence`/`interpretEvidence` 由来）、要求が `requiredLoA` を持ち
 *         選択 VC のいずれかがこれを満たさない場合（`LOA_MISMATCH`、code `10030`）の
 *         場合（VericertsError）。
 */
export async function createPresentationWith(
  credentials: CredentialStore,
  personas: PersonaManager,
  keymanager: KeyManager,
  requestURI: string,
  vcIDs: readonly string[],
  opts?: PresentationRequestOptions,
  signing?: ActiveSignerOptions,
): Promise<CreatedPresentation> {
  const holder = await resolveActiveOwnDidHolder(personas, keymanager, signing);
  const { credentials: selectedVCs, disputed } = await resolveSelectedCredentials(
    credentials,
    vcIDs,
  );
  const request = await parsePresentationRequest(requestURI, opts);
  const heldCredentials = await credentials.listActiveCredentials();

  // own-property.ts の規約に合わせ、未指定のキーは生やさず条件付き展開で落とす（`checkLoa: undefined`
  // を own プロパティとして持たせない）。
  const loaCheck = buildLoaCheck(request);
  const result = await createPresentationImpl(
    request,
    selectedVCs,
    heldCredentials,
    holder.signer,
    holder.did,
    { ...(loaCheck !== undefined ? { checkLoa: loaCheck } : {}) },
  );
  // GDPR Art.16 の訂正権フォールバックとして、提示 VC のいずれかが `markCredentialDisputed`
  // 済みなら `presentationMetadata.disputed` を返し、UI 警告表示（呼び出し側 = extension の責務）の
  // 材料にする。
  return disputed ? { ...result, presentationMetadata: { disputed: true } } : result;
}
