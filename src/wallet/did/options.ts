/**
 * Wallet ファサードの DID 系メソッド（`createDID` / `updateDID` / DID Configuration）の
 * 公開オプション・結果型。`WalletOptions` などの生成オプションは `../options.ts`。
 */

import type { DidDocumentPatch } from '../../internal/identity/did.js';

/**
 * `createDID` のオプション。
 */
export interface CreateDIDOptions {
  /** 保持済みの secp256k1 鍵の ID（指定時はその公開鍵を did:key に）。省略時は P-256 を SLIP-0010 `m/9256'/0'/0'/0'` で新規導出。 */
  readonly keyID?: string;
}

/**
 * `updateDID` のオプション。
 *
 * 差分操作 6 種の定義は {@link DidDocumentPatch} が単独で持ち、本型はその別名にとどめる
 * （メンバごとの JSDoc も同型側にある）。逐語で再宣言すると、片側にだけメンバーを足したときに
 * 「ファサードは受理するがプラグインへ渡らない差分」が黙って生まれる —— プラグインが受け取る
 * 内部の `UpdateOptions` も同じ型を `extends` しているので、公開面と内部を構造で縛っておく。
 *
 * 6 メンバはすべて任意だが、**1 つも指定しない呼び出しは `2010`（`reason: 'empty_update'`）で
 * 拒否する** — 何も変えない「更新」を成功させると、プロパティ名の打ち間違い等の指定ミスに
 * 呼び出し側が気付けない。同じ id の入れ替え（鍵ローテーション）は remove と add を同時に
 * 指定して表現する（削除 → 追加の順で適用する）。
 *
 * 署名鍵は受け取らない。`updateDID` は署名も送信も行わないためである（理由は `DidApi.updateDID`
 * の JSDoc）。
 */
export type UpdateDIDOptions = DidDocumentPatch;

/**
 * `generateDIDConfiguration` が返す Well Known DID Configuration。
 *
 * そのまま JSON 化して `<origin>/.well-known/did-configuration.json` に配置できる構造。
 * プロパティ名は DIF Well Known DID Configuration の文書形式に合わせる（`linked_dids`）。
 */
export interface DIDConfiguration {
  /** DIF Well Known DID Configuration の JSON-LD コンテキスト。 */
  readonly '@context': string;
  /** Domain Linkage Credential（JWT-VC 文字列）の配列。 */
  readonly linked_dids: readonly string[];
}

/**
 * `verifyDIDConfiguration` の検証結果。
 *
 * 取得や検証に失敗したときも結果を返す。`linkedDIDs` は各 Domain Linkage Credential の検証結果で、
 * `valid: false` の場合も参照できる。`errors` は取得失敗や形式不正など、文書全体の失敗理由を表す文字列。
 */
export interface DIDConfigurationVerificationResult {
  /** 検証が成立したか（`did` 指定時は「その DID が有効に紐づいているか」）。 */
  readonly valid: boolean;
  /** `linked_dids` の各エントリの検証結果（取得・パースに失敗した場合は空配列）。 */
  readonly linkedDIDs: readonly LinkedDIDResult[];
  /** 文書レベルの失敗理由（取得失敗・形式不正・指定 DID 未紐づけ）。成功時は未設定。 */
  readonly errors?: readonly string[];
}

/** `verifyDIDConfiguration` が検証した個々の Domain Linkage Credential の結果。 */
export interface LinkedDIDResult {
  /** 検証済みの対象 DID。検証前に失敗して DID を確定できない場合は空文字。 */
  readonly did: string;
  /** この Domain Linkage Credential が有効か。 */
  readonly valid: boolean;
  /** 失敗理由の識別子（有効な場合は未設定）。JWT 本文・URL は含めない。 */
  readonly error?: string;
}
