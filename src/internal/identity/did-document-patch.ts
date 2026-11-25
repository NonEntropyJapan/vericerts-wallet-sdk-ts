/**
 * DID Document の差分適用。
 *
 * `updateDID(did, opts)` が要求する 6 つの差分操作（verificationMethod / service / controller の
 * 追加・削除）を、解決済み DID Document へ適用して次版の Document を組み立てる**純関数**である。
 * DID メソッドごとの公開手段（オンチェーン書き込み・DID Log 追記・HTTPS ホスティング）は
 * この関数の外（`DIDMethod.update`）が担う。差分の適用規則を 1 箇所に置くのは、メソッドごとに
 * 実装すると「did:X では削除できたが did:Y では黙って無視された」という差が出るためである。
 *
 * ## 規則
 *
 * 1. **削除 → 追加の順**に適用する。同じ id の入れ替え（鍵ローテーション）が 1 回の呼び出しで
 *    表現でき、かつ追加が削除に打ち消される順序事故が起きない。**同一呼び出しで同じ id を
 *    remove + add するときだけは、relationship の参照（文字列）を残す**（規則 4 の例外）。
 *    外してしまうと `authentication` / `assertionMethod` が空の Document ができ、ローテーション
 *    したはずの新しい鍵でどの用途の認証も通らなくなる。**埋め込み形式のエントリは残さない** —
 *    それは古い鍵素材そのものであり、残せば失効させたはずの鍵が relationship に生き続ける。
 * 2. **存在しないものの削除は成功にしない**（`2010`）。「削除したつもり」の呼び出し側が古い鍵を
 *    残したまま成功応答を受け取ると、失効したはずの鍵で署名が通り続ける。
 * 3. **既にある id の追加は成功にしない**（`2010`）。黙って置換すると、公開鍵の差し替えが
 *    「追加」の顔で通ってしまう。入れ替えは remove + add を明示的に指定する。
 * 4. VerificationMethod を削除したら、**全 relationship 配列からその参照も外す**
 *    （`authentication` 等）。外さないと解決不能な参照が残った不正な Document になる。
 *    埋め込み形式（参照ではなく VerificationMethod そのもの）も同じ id で照合して外す。
 *    例外は規則 1 のローテーションだけである。
 * 5. 追加は `verificationMethod` 配列にだけ載せ、relationship へは**入れない**。どの
 *    relationship に紐づけるかは `UpdateDIDOptions` が表現していないため、推測しない。
 *
 * ## セキュリティ上の注意
 *
 * - `opts` の各メンバは**自身のプロパティに限って読む**（`ownProperty`）。鎖読みだと、差分を
 *   **指定していない**正当な呼び出しが `Object.prototype.addController` の汚染値を拾い、
 *   **攻撃者の DID が controller として DID Document に載る**（= DID の乗っ取り）。
 *   `removeVerificationMethod` の汚染は逆に、毎回の更新で正規の鍵が落とされる。
 * - 追加する VerificationMethod / Service は `deepSnapshot` で**1 度だけ読んで畳む**。own
 *   アクセサが読むたびに違う値を返すと、GDPR Art.9 ガード（`assertNoSpecialCategoryOnChain`）が
 *   見た値と公開される Document が別物になる（`normalized-log-input.ts` と同じ根拠）。
 *   `deepSnapshot` が畳めるのは**プレーンなコンテナ（素の配列 / プレーンオブジェクト）だけ**で、
 *   クラスインスタンス・`getPrototypeOf` トラップ付き `Proxy` 等は参照のまま返る。返り値が入力と
 *   同一参照なら「畳めなかった」印なので、そこで拒否する（畳めない値を載せると Art.9 ガードを
 *   迂回できる）。
 * - 追加する構造体は id だけでなく**型として要求される全メンバ**を検査してから載せる。
 *   `unknown` を無検査で通すと、鍵素材を欠いた VerificationMethod が DID Document に載る。
 * - 例外の `context` は固定識別子のみで、DID 文字列・鍵・エンドポイントは載せない。
 */

import { deepSnapshot } from '../prototype-safety/deep-snapshot.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import type { DIDDocument, Service, UpdateOptions, VerificationMethod } from './did.js';
import type { RelationshipKey } from './did-document-read.js';
import {
  controllersOf,
  patchFailure,
  RELATIONSHIP_KEYS,
  relationshipEntriesOf,
  relationshipId,
  servicesOf,
  verificationMethodsOf,
} from './did-document-read.js';

/**
 * controller 配列を DID Core の表現へ戻す。
 *
 * 空になった場合はキー自体を落とす（`controller: []` は「controller が空である」という別の
 * 主張になり、`controller` を持たない Document とは意味が違う）。1 件でも配列のまま返すのは、
 * 追加・削除の往復で表現が文字列 ⇄ 配列と揺れないようにするためである。
 */
function withControllers(document: DIDDocument, controllers: readonly string[]): DIDDocument {
  if (controllers.length === 0) {
    const { controller: _dropped, ...rest } = document;
    return rest;
  }
  return { ...document, controller: controllers };
}

/**
 * VerificationMethod を削除し、全 relationship 配列からその参照も外す（規則 2 / 4）。
 *
 * @param keepReferences 同一呼び出しで同じ id を再追加する（鍵ローテーション）なら `true`。
 *   relationship の**参照（文字列）だけ**を残す。埋め込み形式は古い鍵素材そのものなので残さない。
 */
function removeVerificationMethod(
  document: DIDDocument,
  id: string,
  keepReferences: boolean,
): DIDDocument {
  const methods = verificationMethodsOf(document);
  const remaining = methods.filter((method) => method.id !== id);
  if (remaining.length === methods.length) {
    throw patchFailure('verification_method_not_found');
  }
  const relationships: Partial<Record<RelationshipKey, readonly (string | VerificationMethod)[]>> =
    {};
  for (const key of RELATIONSHIP_KEYS) {
    const entries = relationshipEntriesOf(document, key);
    if (entries === undefined) {
      continue;
    }
    relationships[key] = entries.filter(
      (entry) => relationshipId(entry) !== id || (keepReferences && typeof entry === 'string'),
    );
  }
  return { ...document, ...relationships, verificationMethod: remaining };
}

/** Service を削除する（規則 2）。 */
function removeService(document: DIDDocument, id: string): DIDDocument {
  const services = servicesOf(document);
  const remaining = services.filter((service) => service.id !== id);
  if (remaining.length === services.length) {
    throw patchFailure('service_not_found');
  }
  if (remaining.length === 0) {
    const { service: _dropped, ...rest } = document;
    return rest;
  }
  return { ...document, service: remaining };
}

/** controller を削除する（規則 2）。 */
function removeController(document: DIDDocument, controller: string): DIDDocument {
  const controllers = controllersOf(document);
  const remaining = controllers.filter((entry) => entry !== controller);
  if (remaining.length === controllers.length) {
    throw patchFailure('controller_not_found');
  }
  return withControllers(document, remaining);
}

/** own プロパティが非空文字列か。 */
function ownNonEmptyString(source: object, key: string): boolean {
  const value = ownProperty<unknown>(source, key);
  return typeof value === 'string' && value !== '';
}

/**
 * 畳んだ値を `VerificationMethod` として受け取る（規則: id 以外の必須メンバも検査する）。
 *
 * 検査するのは `VerificationMethod` が型として要求する 3 つ（`id` / `type` / `controller`）で、
 * 公開鍵の表現（`publicKeyMultibase` / `publicKeyJwk` …）はメソッドごとに違うためここでは見ない
 * （`did.ts` の型定義と同じ線引き）。
 */
function toVerificationMethod(value: unknown): VerificationMethod {
  if (typeof value !== 'object' || value === null) {
    throw patchFailure('verification_method_invalid');
  }
  if (!ownNonEmptyString(value, 'id')) {
    throw patchFailure('verification_method_id_missing');
  }
  if (!ownNonEmptyString(value, 'type') || !ownNonEmptyString(value, 'controller')) {
    throw patchFailure('verification_method_invalid');
  }
  return value as VerificationMethod;
}

/** 畳んだ値を `Service` として受け取る（`id` / `type` / `serviceEndpoint` を検査する）。 */
function toService(value: unknown): Service {
  if (typeof value !== 'object' || value === null) {
    throw patchFailure('service_invalid');
  }
  if (!ownNonEmptyString(value, 'id')) {
    throw patchFailure('service_id_missing');
  }
  if (!ownNonEmptyString(value, 'type') || ownProperty(value, 'serviceEndpoint') === undefined) {
    throw patchFailure('service_invalid');
  }
  return value as Service;
}

/** VerificationMethod を追加する（規則 3 / 5）。 */
function addVerificationMethod(document: DIDDocument, method: VerificationMethod): DIDDocument {
  const methods = verificationMethodsOf(document);
  if (methods.some((existing) => existing.id === method.id)) {
    throw patchFailure('verification_method_exists');
  }
  return { ...document, verificationMethod: [...methods, method] };
}

/** Service を追加する（規則 3）。 */
function addService(document: DIDDocument, service: Service): DIDDocument {
  const services = servicesOf(document);
  if (services.some((existing) => existing.id === service.id)) {
    throw patchFailure('service_exists');
  }
  return { ...document, service: [...services, service] };
}

/**
 * 追加する構造体を**確定値へ畳む**。畳めない値（クラスインスタンス・`getPrototypeOf` トラップ
 * 付き `Proxy` など）は拒否する。
 *
 * `deepSnapshot` は複製対象でない値を**そのまま返す**ので、戻りが入力と同一参照であることが
 * 「畳めなかった」の印になる。畳めていない値は own アクセサが生き残るため、Art.9 ガードが見た値と
 * 公開される Document を食い違わせられる（モジュール冒頭のセキュリティ注記）。
 */
function foldedOrReject(value: unknown, reason: string): unknown {
  if (value === undefined) {
    return undefined;
  }
  const folded = deepSnapshot(value);
  if (folded === value) {
    throw patchFailure(reason);
  }
  return folded;
}

/** controller を追加する（規則 3）。 */
function addController(document: DIDDocument, controller: string): DIDDocument {
  const controllers = controllersOf(document);
  if (controllers.includes(controller)) {
    throw patchFailure('controller_exists');
  }
  return withControllers(document, [...controllers, controller]);
}

/**
 * 解決済み DID Document に `UpdateDIDOptions` の差分を適用し、次版の Document を返す。
 *
 * 入力の `document` は変更しない（各段で新しいオブジェクトを作る）。差分が 1 つも指定されて
 * いない場合は `2010`（`reason: 'empty_update'`）で拒否する — 何も変えない「更新」を成功させると、
 * 呼び出し側は差分の指定ミス（プロパティ名の打ち間違い等）に気付けない。
 *
 * @param document 解決済みの現行 DID Document。
 * @param opts 差分操作（各メンバは own 限定で 1 度だけ読む）。
 * @returns 差分適用後の DID Document。
 * @throws 差分が空・削除対象が存在しない・追加対象の id が既にある・必須メンバを欠く /
 *         確定値へ畳めない構造体を渡された場合（VericertsError、code `2010`）。
 */
export function applyDidDocumentUpdate(document: DIDDocument, opts: UpdateOptions): DIDDocument {
  // 各メンバはここで **1 度だけ** own 限定に読み、以降は読んだ値だけを使う。
  const removeMethodId = ownProperty<string>(opts, 'removeVerificationMethod');
  const removeServiceId = ownProperty<string>(opts, 'removeService');
  const removedController = ownProperty<string>(opts, 'removeController');
  // 追加される構造体は入れ子まで畳む（own アクセサの再評価で Art.9 ガードを迂回させない）。
  const foldedMethod = foldedOrReject(
    ownProperty<unknown>(opts, 'addVerificationMethod'),
    'verification_method_not_foldable',
  );
  const foldedService = foldedOrReject(
    ownProperty<unknown>(opts, 'addService'),
    'service_not_foldable',
  );
  const addedController = ownProperty<string>(opts, 'addController');
  const addedMethod = foldedMethod === undefined ? undefined : toVerificationMethod(foldedMethod);
  const addedService = foldedService === undefined ? undefined : toService(foldedService);

  let next = document;
  let changed = false;
  // 削除 → 追加の順（規則 1）。同じ id を入れ替える鍵ローテーションでは relationship の参照を保つ。
  if (removeMethodId !== undefined) {
    next = removeVerificationMethod(next, removeMethodId, addedMethod?.id === removeMethodId);
    changed = true;
  }
  if (removeServiceId !== undefined) {
    next = removeService(next, removeServiceId);
    changed = true;
  }
  if (removedController !== undefined) {
    next = removeController(next, removedController);
    changed = true;
  }
  if (addedMethod !== undefined) {
    next = addVerificationMethod(next, addedMethod);
    changed = true;
  }
  if (addedService !== undefined) {
    next = addService(next, addedService);
    changed = true;
  }
  if (addedController !== undefined) {
    next = addController(next, addedController);
    changed = true;
  }
  if (!changed) {
    throw patchFailure('empty_update');
  }
  return next;
}
