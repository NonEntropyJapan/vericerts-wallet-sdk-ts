/**
 * VP に内包された VC 1 件を検証する入口（`credential-results.ts` から切り出し）。
 *
 * 本モジュールはフォーマット判別（JWT-VC / SD-JWT VC / JSON-LD VC / COSE_Sign1 VC）と、対応する
 * 検証モジュールへの振り分けだけを担う。実処理は責務ごとに `credential-entry/` 配下へ分けてある
 * （1 ファイル 300 行の上限を守るため）:
 *
 * - `credential-entry/jwt-vc-entry.ts`: JWT-VC 1 件の検証（`verifyCredential` へ委譲）。
 * - `credential-entry/sd-jwt-vc-entry.ts`: SD-JWT VC 1 件の検証（`verifySdJwt` へ委譲）。
 * - `credential-entry/cose-sniff.ts`: COSE_Sign1（`vc+cose`）の外形判定（未対応の
 *   フォーマットを JWT として読まないための振り分け専用で、検証は行わない）。
 * - `credential-entry/holder-binding.ts`: 提示者との突合（`requireHolderBinding`）。
 * JWT-VC は `sub` と `vp.holder` の一致または委任、SD-JWT VC は `cnf` + KB-JWT。
 * - `credential-entry/entry-input.ts`: 委譲先へ渡す入力の組み立てと鍵 DI の使用地点読み。
 * - `credential-entry/entry-result.ts`: `VerificationResult` の組み立てと payload / ヘッダの読み。
 *
 * 型と公開入口（`verifyEmbeddedCredentials` / `resolvePresentationVerificationFields`）は
 * `credential-results.ts` 側にある。
 *
 * どの段の不成立も例外ではなく `valid: false` として返す（他の VC の結果を失わないため）。
 *
 * セキュリティ上の注意:
 * - `errors` にはエラーコードだけを入れ、VC 本文・開示値・JWT を含めない。
 */

import { ErrorCodes } from '../../errors.js';
import { spendWork } from '../../primitives/presentation-work-budget.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { VCFormat } from '../format-negotiation/types.js';
import { looksLikeCoseSign1 } from './credential-entry/cose-sniff.js';
import { failed } from './credential-entry/entry-result.js';
import { verifyJwtVcEntry } from './credential-entry/jwt-vc-entry.js';
import { verifySdJwtVcEntry } from './credential-entry/sd-jwt-vc-entry.js';
import { verifyScopeOf } from './credential-entry/verify-scope.js';
import type {
  EmbeddedCredentialEntry,
  EmbeddedCredentialVerifyInput,
  VerificationResult,
} from './credential-results.js';

/**
 * 内包 VC 1 件を、フォーマットを判別して検証する。
 *
 * @param entry `verifiableCredential` の要素。
 * @param index 要素の位置（`credentialKey` へ渡す）。
 * @param input 発行者鍵の DI・FC-11 の Trust Chain・時刻とスキュー。
 * @returns 当該 VC の検証結果（例外は投げない）。
 */
export function verifyEmbeddedCredentialEntry(
  entry: EmbeddedCredentialEntry,
  index: number,
  input: EmbeddedCredentialVerifyInput,
): VerificationResult {
  if (typeof entry !== 'string') {
    // JSON-LD VC（Data Integrity proof）の `ldp_vc` / `bbs+` は未実装で、
    // 本 SDK は検証手段を持たない。未対応は成功にしない（fail-closed）。ここでは署名検証を一度も
    // 行っていないので、「署名が不正だった」と読める `SIG_INVALID`（3010）ではなく、未対応の構造で
    // あることを示す `VC_SCHEMA_INVALID`（3002）を返す。cryptosuite の種類は診断ラベルだけに影響する。
    return failed(dataIntegrityFormatOf(entry), '', ErrorCodes.VC_SCHEMA_INVALID, input);
  }
  if (looksLikeCoseSign1(entry)) {
    // COSE_Sign1 VC（`vc+cose`）も未実装。JWT として読ませると
    // 「デコード不能」として `SIG_INVALID`（3010）に落ち、署名を検証したかのように誤読させる。
    // ここで先に捕まえ、JSON-LD VC と同じく未対応構造を示す 3002 を返す（署名検証は行わない）。
    return failed('vc+cose', '', ErrorCodes.VC_SCHEMA_INVALID, input);
  }
  // 署名検証を伴う検証の前に仕事量を計上する。SD-JWT VC は発行者署名 + KB-JWT の最大 2 回。
  const isSdJwt = entry.includes('~');
  spendWork(verifyScopeOf(input)?.budget, 'signatures', isSdJwt ? 2 : 1);
  return isSdJwt ? verifySdJwtVcEntry(entry, index, input) : verifyJwtVcEntry(entry, index, input);
}

/** BBS+ の cryptosuite 識別子（Data Integrity BBS Cryptosuites v1.0）。 */
const BBS_CRYPTOSUITE = 'bbs-2023';

/**
 * オブジェクト形の内包 VC に付ける診断用フォーマット識別子を決める。
 *
 * `ldp_vc` と `bbs+` はどちらも Data Integrity VC（未実装）であり、**拒否の判定はこの関数の
 * 結果に一切依存しない**（いずれも `VC_SCHEMA_INVALID` で `valid: false`）。ここで見るのは、
 * 結果に載る `format` を実態に合わせるためだけである。`vc+cose` の外形判定（`cose-sniff.ts`）と
 * 違い、振り分け先を変える判定ではない。
 *
 * `entry` / `proof` は外部入力の JSON なので、フィールドは own 限定で読む（鎖読みすると当該キーを
 * **持たない** VC で `Object.prototype` の汚染値を拾い、`ldp_vc` が `bbs+` と表示されうる）。
 * 判断がつかない入力（`proof` 欠落・配列・複数 proof）は既定の `ldp_vc` に倒す。
 *
 * @param entry `verifiableCredential` の要素（オブジェクトのもの）。
 * @returns `bbs-2023` を名乗る Data Integrity proof なら `'bbs+'`、それ以外は `'ldp_vc'`。
 */
function dataIntegrityFormatOf(entry: Readonly<Record<string, unknown>>): VCFormat {
  const proof = ownProperty<unknown>(entry, 'proof');
  if (typeof proof !== 'object' || proof === null) {
    return 'ldp_vc';
  }
  return ownProperty<unknown>(proof, 'cryptosuite') === BBS_CRYPTOSUITE ? 'bbs+' : 'ldp_vc';
}
