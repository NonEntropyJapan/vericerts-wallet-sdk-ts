/**
 * DID Document の**読み取り**ヘルパー（`did-document-patch.ts` の差分適用が使う）。
 *
 * 差分適用の規則そのものは `did-document-patch.ts` が持ち、本モジュールは「解決済み Document から
 * 配列を取り出す」ところだけを担う。分けているのは行数のためだけではない —— ここにある関数は
 * **すべて同じ 1 つの不変条件**を守るためにあり、1 か所に集めておかないと片方だけ素の鎖読みに
 * 戻るリファクタが成立してしまうからである。
 *
 * ## 不変条件: **型が必須と書いていても、実体はネットワーク由来である**
 *
 * `applyDidDocumentUpdate` の `document` は `resolver.resolve(did)` の戻り値で、ネットワーク
 * resolver は解決出口で配列性も検査する（{@link assertNetworkDidDocumentShape}）が、欠落は残るし、
 * storage 上の控えは検査前の形であり得る。したがって
 * `verificationMethod` を持たない文書、`authentication: 'did:web:x#k'` のように**配列でない値**を
 * 置いた文書、`service` / `controller` が別型の文書が普通に到達する。読み手はいずれも `.filter` /
 * `.some` / `.includes` なので、素で触ると公開 API `wallet.updateDID` から**生の `TypeError`** が
 * 漏れる（`wallet/did/update.ts` に try/catch は無い）。したがってここで `2010` へ正規化する。
 *
 * 読み取りに失敗した箇所は `2010` の reason（`controller_unreadable`、
 * `verification_method_unreadable`、`relationship_unreadable`、`service_unreadable`）で識別できる。
 *
 * ## 倒し方
 *
 * - **持たない（`undefined`）と読めない（配列でない）は区別する。** 前者は DID Core 上の正当な状態
 *   なので `[]`（relationship は `undefined`）に倒し、後者は `2010` で**拒否**する。
 * - `[]` に倒さない理由は fail-closed である。既存の要素を 1 つも持たない Document として扱うと、
 *   **鍵や Service の総入れ替えが「追加」の顔で通る**（規則 3 の「既にある id の追加は成功にしない」が
 *   空振りする）。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import type { DIDDocument, Service, VerificationMethod } from './did.js';

/** 差分適用の失敗（`2010`、再試行不可）。理由は固定識別子のみ。 */
export function patchFailure(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.DID_DOC_INVALID, { context: { reason } });
}

/** relationship 配列のキー（VerificationMethod を参照し得る DID Core のメンバ）。 */
export const RELATIONSHIP_KEYS = [
  'authentication',
  'assertionMethod',
  'keyAgreement',
  'capabilityInvocation',
  'capabilityDelegation',
] as const satisfies readonly (keyof DIDDocument)[];

/**
 * DID Document の `verificationMethod` / 各 relationship / `service` 1 配列あたりの最大件数。
 *
 * ネットワーク由来の文書は 1 MiB まで届き、バイト数だけでは件数（≒ 83,000 件）に上限が無い。
 * 件数に比例・二乗して走る読み手（検証鍵の選択・差分適用）を署名検証前に飽和させられるため、
 * 配列読みの共通入口で打ち切る。実用上の文書は各配列とも数件〜十数件。
 */
export const MAX_DID_DOCUMENT_ARRAY_ENTRIES = 256;

/** relationship 配列のキー型。 */
export type RelationshipKey = (typeof RELATIONSHIP_KEYS)[number];

/**
 * 配列要素が「`id` が文字列の非 null オブジェクト」か。
 *
 * `verificationMethod: [null]` や `service: ['x']` のような**要素レベルの不正**は配列性の検査を
 * 通り抜け、後続の読み手（`.id` / `.find(entry => entry.type …)` / `vm.publicKeyJwk`）が公開 API から
 * 生の `TypeError` を漏らす。要素の型は配列読みと同じ位置で検査し、全読み手で共有する。
 */
function isIdentifiedObject(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    typeof ownProperty<unknown>(value, 'id') === 'string'
  );
}

/** relationship の要素（参照文字列または埋め込み VerificationMethod）から id を取り出す。 */
export function relationshipId(entry: string | VerificationMethod): string | undefined {
  if (typeof entry === 'string') {
    return entry;
  }
  return ownProperty<string>(entry, 'id');
}

/**
 * `document` の controller を常に配列として読む（DID Core は文字列と配列の両形を許す）。
 *
 * {@link verificationMethodsOf} と同じ理由で**配列性を検査する**。`controller` は型として
 * 省略可能だが、実体はネットワーク resolver が返した JSON なので、文字列でも配列でもない値
 * （オブジェクト・数値・汚染値）が普通に到達する。素で返すと `:removeController` の `.filter` /
 * `addController` の `.includes` が公開 API `wallet.updateDID` から**生の `TypeError`** を漏らす。
 */
export function controllersOf(document: DIDDocument): readonly string[] {
  const controller = ownProperty<unknown>(document, 'controller');
  if (controller === undefined) {
    return [];
  }
  if (typeof controller === 'string') {
    return [controller];
  }
  if (!Array.isArray(controller)) {
    throw patchFailure('controller_unreadable');
  }
  return controller;
}

/**
 * `document.verificationMethod` を常に配列として読む。
 *
 * **型が必須と書いていても実体はネットワーク由来である。** `current` は `resolver.resolve(did)` の
 * 戻り値で、ネットワーク resolver（`did-web-fetch.ts` / `ipid/gateway.ts`）が検査するのは `id` の
 * 一致だけである。`verificationMethod` を持たない did:web / did:ipid 文書を返されたときに
 * `document.verificationMethod.filter(...)` と素で触ると、公開 API `wallet.updateDID` から
 * **生の `TypeError`** が漏れる（仕様上は `2010`）。隣の service 読み（`document.service ?? []`）と
 * 揃えて 1 か所で吸収する。
 *
 * 配列でない値（汚染された文字列など）は `[]` に倒さず拒否する — `[]` に倒すと、既存の鍵を
 * 1 つも持たない Document として「追加」が成功し、**鍵の総入れ替えが追加の顔で通る**。
 */
export function verificationMethodsOf(document: DIDDocument): readonly VerificationMethod[] {
  const methods = ownProperty<readonly VerificationMethod[]>(document, 'verificationMethod');
  if (methods === undefined) {
    return [];
  }
  if (!Array.isArray(methods)) {
    throw patchFailure('verification_method_unreadable');
  }
  if (methods.length > MAX_DID_DOCUMENT_ARRAY_ENTRIES) {
    throw patchFailure('verification_method_too_many');
  }
  if (!methods.every(isIdentifiedObject)) {
    throw patchFailure('verification_method_unreadable');
  }
  return methods;
}

/**
 * `document[key]`（relationship 配列）を読む。持たない場合は `undefined`。
 *
 * {@link verificationMethodsOf} と同じ理由で配列性を検査する。`authentication: 'did:web:x#k'`
 * のように**文字列 1 個を直に置いた**文書は DID Core としては不正だが、ネットワーク resolver は
 * `id` の一致しか検査しないので到達する。素で `.filter` を呼ぶと生の `TypeError` が漏れる。
 *
 * 持たない（`undefined`）と読めない（配列でない）は区別する — 前者は「その用途の鍵が無い」
 * という正当な状態で、後者は現行 Document を読めていない状態なので拒否側に倒す。
 */
export function relationshipEntriesOf(
  document: DIDDocument,
  key: RelationshipKey,
): readonly (string | VerificationMethod)[] | undefined {
  const entries = ownProperty<readonly (string | VerificationMethod)[]>(document, key);
  if (entries === undefined) {
    return undefined;
  }
  if (!Array.isArray(entries)) {
    throw patchFailure('relationship_unreadable');
  }
  if (entries.length > MAX_DID_DOCUMENT_ARRAY_ENTRIES) {
    throw patchFailure('relationship_too_many');
  }
  if (!entries.every((entry) => typeof entry === 'string' || isIdentifiedObject(entry))) {
    throw patchFailure('relationship_unreadable');
  }
  return entries;
}

/**
 * `document.service` を常に配列として読む。
 *
 * {@link verificationMethodsOf} と同じ理由で配列性を検査する。`service` は DID Core でも省略可能
 * なので `undefined` は `[]` に倒すが、配列でない値は**拒否する** — `[]` に倒すと、既存の Service を
 * 1 つも持たない Document として「追加」が成功し、`serviceEndpoint` の差し替えが追加の顔で通る。
 */
export function servicesOf(document: DIDDocument): readonly Service[] {
  const services = ownProperty<readonly Service[]>(document, 'service');
  if (services === undefined) {
    return [];
  }
  if (!Array.isArray(services)) {
    throw patchFailure('service_unreadable');
  }
  if (services.length > MAX_DID_DOCUMENT_ARRAY_ENTRIES) {
    throw patchFailure('service_too_many');
  }
  if (!services.every(isIdentifiedObject)) {
    throw patchFailure('service_unreadable');
  }
  return services;
}

/**
 * ネットワークから解決した DID Document の配列形状を検査する。
 *
 * `verificationMethod` / relationship / `service` が**存在するのに配列でない**とき
 * `DID_DOC_INVALID`（2010）にする。欠落（`undefined`）は DID Core の省略なので拒否しない
 * （検証鍵が要る呼び出し側が候補なしを 2010 に倒す）。did:web / did:webvh / did:ipid
 * の解決出口が共有する。
 *
 * @param document 解決結果。
 * @throws 配列でないメンバがある場合（VericertsError、code `2010`）。
 */
export function assertNetworkDidDocumentShape(document: DIDDocument): void {
  verificationMethodsOf(document);
  servicesOf(document);
  for (const key of RELATIONSHIP_KEYS) {
    relationshipEntriesOf(document, key);
  }
}
