/**
 * Wallet ファサードで JWT-VP の内包 VC を検証するための発行者鍵解決。
 *
 * `verifyPresentation` プリミティブは内包 VC の発行者鍵を `credentialKey` で DI する（holder 鍵と
 * 同じく DID 解決は credential の責務外）。ファサードは resolver を持つので、その DI をここで埋める。
 *
 * **順序**: DID 解決は `verifyPresentation` が **VP 署名を検証し終えてから**行う。先に解決すると、
 * 署名を検証していない VP に書かれた任意の DID へネットワークアクセスさせられる（未検証入力を起点に
 * した SSRF / DoS の増幅）。そのためファサードは「VP 検証 → 内包 VC の鍵解決 → 内包 VC 検証」の
 * 2 パスで組み立て、プリミティブへ `credentialKey` を渡す 1 パス実行はしない。
 *
 * **fail-closed**: 鍵解決に失敗した VC（DID 未解決・未対応メソッド・JWK を持たない鍵・JSON-LD VC・
 * ファンアウト上限超過）は `undefined` を返し、当該 VC を `valid: false` にする。解決できなかった VC を
 * 「検証済み」にはしない。
 *
 * **ファンアウト上限**: 内包 VC の件数に上限は無いため、発行者 DID 解決は上限付きラッパー
 * （`createBoundedResolver`）越しに行い、同じ DID の解決をまとめ、並列数と相異なる DID の数を制限する。
 *
 * 配置: 旧 `wallet/presentation-credentials.ts`。`wallet/` 直下がディレクトリ 2000 行の上限に達した
 * ため、VP 内包 VC 用のサブディレクトリへ移すと同時に、提示者突合（`requireHolderBinding`）と
 * 実効バインド値（`PresentationBinding`）の中継を足した。
 */

import type {
  CredentialVerifierKey,
  IssuerTrustOption,
  VerifiedPresentation,
} from '../../internal/credential/index.js';
import { resolvePresentationVerificationFields } from '../../internal/credential/index.js';
// 内包 VC を検証しない内部経路の型のためバレルには出していない（実体から取る）。
import type { VerifiedPresentationClaims } from '../../internal/credential/presentation/presentation.js';
import type { DidResolverLike } from '../../internal/identity/bounded-resolver.js';
import { createBoundedResolver } from '../../internal/identity/bounded-resolver.js';
import type { PresentationWorkBudget } from '../../internal/primitives/presentation-work-budget.js';
import { ownProperty } from '../../internal/prototype-safety/own-property.js';
import type { TrustedIssuerList } from '../../internal/trusted-issuer/types.js';
import { resolveIssuerVerifierKey, resolveSdJwtIssuerKey } from '../issuer-key.js';

/**
 * 内包 VC 1 件の発行者検証鍵を解決する（解決できなければ `undefined`）。
 *
 * JSON-LD VC（object）は Data Integrity proof の検証手段を SDK が持たないため対象外。
 */
async function resolveEmbeddedKey(
  resolver: DidResolverLike,
  entry: string | Readonly<Record<string, unknown>>,
): Promise<CredentialVerifierKey | undefined> {
  if (typeof entry !== 'string') {
    return undefined;
  }
  try {
    if (entry.includes('~')) {
      return { publicKeyJwk: await resolveSdJwtIssuerKey(resolver, entry) };
    }
    return await resolveIssuerVerifierKey(resolver, entry);
  } catch {
    // 解決失敗は当該 VC の検証不能（`valid: false`）として扱い、VP 全体の例外にはしない。
    // 1 件の解決失敗で他の VC の結果まで失うと `credentialResults` の意味が無くなるため。
    // 上限付きラッパーが投げるファンアウト上限超過（`2001`）も同じ経路で fail-closed になる。
    return undefined;
  }
}

/**
 * 内包 SD-JWT VC の KB-JWT 検証へ中継する**実効**バインド値。
 *
 * ファサードは検証経路が 2 つあり、実効値の出どころが異なるため呼び出し側が明示的に渡す:
 *
 * - replay 検知経路: `nonceContext` の束縛値と照合済みの**実測 `aud`**（呼び出し側は
 *   `expectedAudience` を省略できるため、オプション値だけでは KB-JWT を照合できない）。
 * - 通常経路: `expectedAudience` / `expectedNonce`（束縛モードでは payload と一致確認済み）。
 *
 * どちらも「検証済みの値」だけを渡すこと。未検証の payload 値を渡すと、KB-JWT の `aud` / `nonce`
 * 照合が攻撃者が自分で決めた値どうしの突合になり、検査として意味を成さない。
 */
export interface PresentationBinding {
  /** 実効 audience（OID4VP の `aud`）。`undefined` なら KB-JWT の `aud` を照合しない。 */
  readonly audience: string | undefined;
  /** 実効 nonce。`undefined` なら KB-JWT の `nonce` を照合しない。 */
  readonly nonce: string | undefined;
}

/**
 * VP 署名検証済みの結果に、内包 VC の検証結果（`credentialResults` / `valid` / `holderDID`）を足す。
 *
 * @param resolver 発行者 DID の解決委譲先。
 * @param verified VP レベルの検証を終えた結果。内包 VC の検証結果は**受け取らない**（本関数が
 *                 発行者鍵を DID 解決で補完して 1 回だけ組み立てるため、上流は未検証の
 *                 `header` / `payload` / `asserted` だけを渡す）。VP は検査済みメンバごと
 *                 （`asserted`）受け取り、`holder` / `verifiableCredential` を読み直さない。
 * @param opts ファサードのオプション（`issuerTrust` / `clockSkewSeconds` / `requireHolderBinding`
 *             を自身のプロパティに限って読む）。
 * @param nowSeconds 時刻評価の基準（未指定なら現在時刻）。
 * @param binding KB-JWT 検証へ中継する実効 audience / nonce（`PresentationBinding`）。
 * @returns 内包 VC の検証結果を反映した `VerifiedPresentation`。
 */
export async function attachCredentialResults(
  resolver: DidResolverLike,
  verified: Pick<VerifiedPresentationClaims, 'header' | 'payload' | 'asserted'>,
  opts: object,
  nowSeconds: number | undefined,
  binding: PresentationBinding,
): Promise<VerifiedPresentation> {
  const entries = verified.asserted.verifiableCredential;
  // 上限付きラッパーは VP 1 件ぶんのスコープ。`Promise.all` は残すが、実際の外部 I/O は
  // ラッパーで重複を除き、並列数と相異なる DID 数を制限する。上限を超えた DID の
  // 解決は `2001` で失敗し、既存の fail-closed 経路を通って当該 VC が `valid: false` になる。
  const bounded = createBoundedResolver(resolver);
  const keys = await Promise.all(entries.map((entry) => resolveEmbeddedKey(bounded, entry)));
  // `issuerTrust` は継承値を拾うと FC-11 の突合材料が攻撃者制御になるため own 限定で読む。
  // `clockSkewSeconds` も同じ理由で own 限定で読み、**内包 VC の検証へ必ず中継する**
  // （落とすと VP 側の厳格化指定が無視され、失効直後の内包 VC が valid: true で通る）。
  const issuerTrust = ownProperty<IssuerTrustOption>(opts, 'issuerTrust');
  const clockSkewSeconds = ownProperty<number>(opts, 'clockSkewSeconds');
  // 提示者との突合も own 限定で読む。継承値を拾うと、渡していない呼び出しが黙って
  // 厳格化され、bearer VC を含む正当な提示が一律 3012 に落ちる（可用性の欠陥）。
  const requireHolderBinding = ownProperty<boolean>(opts, 'requireHolderBinding');
  // Trusted Issuer List。継承値を拾うと、list を**渡していない**呼び出しが
  // 攻撃者制御の `Object.prototype` 汚染値を「呼び出し側が渡した信頼リスト」として採用してしまう
  // ため own 限定で読む（`issuerTrust` と同じ理由）。
  const trustedIssuerList = ownProperty<TrustedIssuerList>(opts, 'trustedIssuerList');
  // 仕事量の共有予算。own 限定で読み、内包 VC 検証へそのまま中継する。
  const workBudget = ownProperty<PresentationWorkBudget>(opts, 'workBudget');
  const fields = resolvePresentationVerificationFields(
    verified.asserted,
    {
      credentialKey: ({ index }: { index: number }) => keys[index],
      issuerTrust,
      clockSkewSeconds,
      requireHolderBinding,
      trustedIssuerList,
      workBudget,
      // 内包 VC 検証は `expectedAudience` / `expectedNonce` として実効バインド値を読む。
      expectedAudience: binding.audience,
      expectedNonce: binding.nonce,
    },
    nowSeconds ?? Math.floor(Date.now() / 1000),
  );
  // `{ ...verified, ...fields }` にはしない。`fields` は失敗が無いとき `errors` キー自体を持たない
  // ため、入力側に `errors` が付いていると消えずに残り「`valid: true` なのに errors がある」と
  // いう矛盾した結果になる（引数の型が `credentialResults` 系フィールドを含まないのはそのため）。
  return {
    header: verified.header,
    payload: verified.payload,
    presentation: verified.asserted.vp,
    ...fields,
  };
}
