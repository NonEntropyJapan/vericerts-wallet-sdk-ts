/**
 * Wallet の DID 管理と ERC-1056 controller 操作に利用する API。
 */

import type { UnsignedTransaction } from '../../internal/delegation/index.js';
import type { DIDDocument, DIDMethod } from '../../internal/identity/did.js';
import type {
  CreateDIDOptions,
  DIDConfiguration,
  DIDConfigurationVerificationResult,
  UpdateDIDOptions,
} from './options.js';

/**
 * DID 管理・ERC-1056 controller 操作の Wallet ファサード API。
 */
export interface DidApi {
  /**
   * DID を生成し、DID Document を storage に永続化する。新規に作る did:key は **P-256（ES256）**。
   *
   * @param method DID メソッド名。現在は `'key'` のみ対応。
   * @param opts 生成オプション（keyID 省略時は P-256 の鍵を既定パス `m/9256'/0'/0'/0'` で新規導出。keyID 指定時は
   *        呼び出し側が保持済みの既存鍵の公開鍵を did:key にする）。
   * @returns 生成された DID Document。
   * @throws `method` が `'key'` 以外の場合（VericertsError、code `2002`）、
   *         指定 keyID が未登録の場合（VericertsError、code `1004`）。
   */
  createDID(method: string, opts?: CreateDIDOptions): Promise<DIDDocument>;
  /**
   * DID 文字列を DID Document に解決する（登録メソッドへ委譲）。
   *
   * @param did DID 文字列。
   * @returns DID Document。
   * @throws DID 形式違反の場合（VericertsError、code `2001`）、
   *         未登録メソッドの場合（VericertsError、code `2002`）。
   */
  resolveDID(did: string): Promise<DIDDocument>;
  /**
   * DID Document を更新する。
   *
   * 現行 Document を解決し、`opts` の差分（verificationMethod / service / controller の追加・削除）
   * を適用し、GDPR Art.9 特別カテゴリ属性ガードを通してから、公開を DID メソッドプラグインへ
   * 委譲する。差分適用とガードは DID メソッドに依らない共通規則なのでファサード側で行い、
   * プラグインの責務は「渡された次版 Document を自分のやり方で公開すること」だけである。
   *
   * **署名も送信も行わない。** 署名を要する更新の成果物（did:webvh の署名付き Log
   * エントリ、did:ethr の ERC-1056 トランザクション）は本 API の戻り値では表現できないため、
   * それぞれ専用 API（`updateDidWebVh` / `buildSetControllerTx` /
   * `buildRemoveControllerTx`）を使う。したがって `UpdateDIDOptions` は署名鍵を受け取らない。
   *
   * **不変な DID メソッド（did:key / did:jwk / did:peer / did:pkh / did:jwt）は `2002` で拒否する。**
   * これらは `resolveDID` が DID 文字列から Document を決定論的に再構築するため、更新を許すと
   * `getDID`（storage のローカル控え）と `resolveDID` が恒久的に食い違う。
   *
   * ローカル控えは**公開が成功した後**、かつ**既に控えがある DID についてだけ**書き戻す
   * （`getDID` と `resolveDID` を食い違わせない。`update.ts` の JSDoc 参照）。
   *
   * @param did 更新対象の DID 文字列。
   * @param opts 差分操作（各メンバは own 限定で 1 度だけ読む）。
   * @returns 公開後の DID Document。
   * @throws DID 形式違反（VericertsError、code `2001`）、未登録・更新非対応の DID メソッド
   *         （`2002`）、解決失敗（`2003`）、差分適用の失敗 — 差分が空・削除対象が無い・追加対象の
   *         id が既にある（`2010`）、GDPR Art.9 特別カテゴリ属性を含む場合（`10601`）。
   *
   * @experimental 挙動・シグネチャは変更される場合がある。v1.0 で `@stable` へ昇格予定。
   */
  updateDID(did: string, opts: UpdateDIDOptions): Promise<DIDDocument>;
  /**
   * storage に保存済みの DID Document を取得する。
   *
   * @param did DID 文字列。
   * @returns 保存済み DID Document。未保存なら `null`。
   * @throws 保存データ破損で parse に失敗した場合（VericertsError、code `2001`）。
   */
  getDID(did: string): Promise<DIDDocument | null>;
  /**
   * storage に保存済みの全 DID 文字列を返す。
   *
   * @returns DID 文字列の配列（該当なしは空配列）。
   */
  listDIDs(): Promise<string[]>;
  /**
   * カスタム DID メソッドプラグインを登録する。
   *
   * `createWallet` が登録したメソッドに加えて、利用者が独自メソッドを後から
   * 追加できる。登録後は `resolveDID` が当該メソッド名の DID を本プラグインへディスパッチする。
   * 同名メソッドは上書きする（`Resolver.register` と同じ扱い）。
   *
   * @param method 登録する DID メソッドプラグイン。
   */
  registerDIDMethod(method: DIDMethod): void;
  /**
   * Well Known DID Configuration（Domain Linkage Credential）を生成する。
   *
   * 指定 DID を issuer / credentialSubject.id とする self-issued な Domain Linkage Credential を
   * 発行し、`.well-known/did-configuration.json` に配置できる JSON 構造に包んで返す。署名鍵は
   * アクティブペルソナから解決し、その DID が `did` と一致することまで確認する。
   *
   * @param did 紐づける DID（アクティブペルソナの DID と一致する必要がある）。
   * @param origin ドメインオリジン（例: `https://example.com`）。
   * @returns `.well-known/did-configuration.json` に配置可能な JSON 構造。
   * @throws 指定 DID の署名鍵が利用できない場合（VericertsError、code `2007`）。
   */
  generateDIDConfiguration(did: string, origin: string): Promise<DIDConfiguration>;
  /**
   * ドメインの Well Known DID Configuration を検証する。
   *
   * `<origin>/.well-known/did-configuration.json` を取得し、含まれる各 Domain Linkage Credential
   * の署名・self-issued・`origin` 一致を検証する。取得・パース・検証の失敗時は結果の
   * `errors` / `linkedDIDs[].error` で失敗理由を返す。
   *
   * @param origin 検証対象ドメインオリジン（HTTPS 必須）。
   * @param did 指定時は「この DID が有効な DLC で紐づいているか」のみを判定する（他 DID の DLC の
   *        失敗では `valid` を false にしない）。省略時は全 DLC が有効であることを要求する。
   * @returns 検証結果（例外は投げない）。
   */
  verifyDIDConfiguration(origin: string, did?: string): Promise<DIDConfigurationVerificationResult>;
  /**
   * did:ethr の現在の controller（所有者）をオンチェーンイベントから検出する。
   *
   * `rpcUrls` で設定したチェーンの ERC-1056 イベントを走査し、controller 連鎖をたどって
   * 最終的な controller の did:ethr 文字列を返す。
   *
   * @param did 対象の did:ethr 文字列。
   * @returns controller を表す did:ethr 文字列。
   * @throws DID 形式不正（code `2001`）・未設定チェーン（code `2003`）・
   *         controller 未設定（code `2006`）・循環参照（code `2030`）の場合（VericertsError）。
   */
  detectController(did: string): Promise<string>;
  /**
   * controller を設定する未署名トランザクションを構築する。
   *
   * ERC-1056 の `changeOwner(identity, newOwner)` を呼び、`did` の owner を `controllerDid` の
   * アドレスへ変更する未署名 Tx を返す。実送信（署名・ブロードキャスト）は呼び出し側の責務。
   *
   * @param did 対象の did:ethr 文字列。
   * @param controllerDid 新しい controller の did:ethr 文字列。
   * @param registryAddress ERC-1056 レジストリアドレス（省略時は標準アドレス）。
   * @returns 未署名トランザクション。
   * @throws DID 形式不正・レジストリアドレス形式不正（いずれも code `2001`）の場合（VericertsError）。
   */
  buildSetControllerTx(
    did: string,
    controllerDid: string,
    registryAddress?: string,
  ): UnsignedTransaction;
  /**
   * controller を削除する未署名トランザクションを構築する。
   *
   * ERC-1056 の `changeOwner(identity, identity)` で owner を identity 自身に戻し、委任を解除する
   * 未署名 Tx を返す。実送信は呼び出し側の責務。
   *
   * @param did 対象の did:ethr 文字列。
   * @param registryAddress ERC-1056 レジストリアドレス（省略時は標準アドレス）。
   * @returns 未署名トランザクション。
   * @throws DID 形式不正・レジストリアドレス形式不正（いずれも code `2001`）の場合（VericertsError）。
   */
  buildRemoveControllerTx(did: string, registryAddress?: string): UnsignedTransaction;
}
