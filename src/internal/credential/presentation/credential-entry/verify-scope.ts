/**
 * `verifyEmbeddedCredentials` 1 回ぶんの共有状態（仕事量の予算と信頼リスト索引）。
 *
 * 入力オブジェクトを複製して予算や索引を足さない。`Object.create(proto)` で DI を継承させている呼び出し
 * （`credentialKey` のプロトタイプメソッド実装など）を、スプレッドによる複製が黙って壊すため。代わりに
 * 入力オブジェクトをキーとする `WeakMap` に、検証の同期区間だけ状態を載せる。
 */

import {
  newPresentationWorkBudget,
  type PresentationWorkBudget,
} from '../../../primitives/presentation-work-budget.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import {
  buildTrustedIssuerIndex,
  type TrustedIssuerIndex,
} from '../../../trusted-issuer/issuer-index.js';
import type { EmbeddedCredentialVerifyInput } from '../credential-results.js';

/** 1 回の検証で全要素が共有する状態。 */
export interface VerifyScope {
  readonly budget: PresentationWorkBudget;
  readonly trustedIssuerIndex: TrustedIssuerIndex | undefined;
}

const scopes = new WeakMap<object, VerifyScope>();

/** `input` に紐づく現在の検証スコープ（`runInVerifyScope` の外では `undefined`）。 */
export function verifyScopeOf(input: object): VerifyScope | undefined {
  return scopes.get(input);
}

/**
 * 検証スコープを作って `run` を実行する。予算は呼び出し側が渡したもの（`input.workBudget`）を使い、無ければ
 * VP 専用に作る。索引は `trustedIssuerList` があるときだけ 1 度作る。`run` は同期でなければならない。
 */
export function runInVerifyScope<T>(input: EmbeddedCredentialVerifyInput, run: () => T): T {
  const list = ownProperty<EmbeddedCredentialVerifyInput['trustedIssuerList']>(
    input,
    'trustedIssuerList',
  );
  scopes.set(input, {
    budget: ownProperty<PresentationWorkBudget>(input, 'workBudget') ?? newPresentationWorkBudget(),
    trustedIssuerIndex: list === undefined ? undefined : buildTrustedIssuerIndex(list),
  });
  try {
    return run();
  } finally {
    scopes.delete(input);
  }
}
