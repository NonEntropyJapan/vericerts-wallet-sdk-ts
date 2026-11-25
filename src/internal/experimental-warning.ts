/**
 * `@experimental` 公開 API のランタイム警告。
 *
 * `@experimental` / `@deprecated` の公開 API は **API 名ごとに 1 プロセス 1 回**警告する。
 * Logger が未注入の場合は `console.warn` を使う。このモジュールは警告済みの API 名を
 * `Set` に記録する。
 *
 * **警告を掛けられるのは呼び出し可能な公開 API だけである。** 型・インターフェースはランタイムに
 * 存在せず、文字列などのプリミティブ定数は読み出しを観測できる呼び出し点を持たないため、
 * どちらも警告の対象にできない。
 *
 * 配線は対象 API を公開するサブパスのバレルで行う。内部呼び出し（SDK 自身が
 * 内部実装として同じ関数を使う経路）は素の実装をそのまま参照するため警告を出さない。
 * 警告は**外部利用者が公開 API を呼んだこと**を知らせるものなので、これが正しい境界である。
 *
 * @internal
 */

import { defineDataProperty } from './prototype-safety/define-data-property.js';
import { ownProperty } from './prototype-safety/own-property.js';

/**
 * 警告を抑止する環境変数名。
 *
 * 値が `'1'` / `'true'` のとき警告を出さない。テストランナーや CI のログが
 * 警告で埋まるのを避けるための逃がし口で、既定（未設定）では警告する。
 *
 * @internal
 */
export const SUPPRESS_EXPERIMENTAL_WARNINGS_ENV =
  'VERICERTS_WALLET_SDK_SUPPRESS_EXPERIMENTAL_WARNINGS';

/** 警告済みの API 名。プロセス内で一度だけ警告するための記録。 */
const warnedApis = new Set<string>();
const nodeProcessWarningApis = new Set<string>();
const nodeProcessWarningKey = (apiName: string): symbol =>
  Symbol.for(`vericerts-wallet-sdk:experimental-warning:${apiName}`);

function nodeWarningHost(): object | undefined {
  const proc = ownProperty<unknown>(globalThis, 'process');
  if (typeof proc !== 'object' || proc === null) return undefined;

  const versionsDescriptor = Object.getOwnPropertyDescriptor(proc, 'versions');
  const versions = versionsDescriptor && ownProperty<unknown>(versionsDescriptor, 'value');
  if (typeof versions !== 'object' || versions === null) return undefined;

  const nodeDescriptor = Object.getOwnPropertyDescriptor(versions, 'node');
  return nodeDescriptor && typeof ownProperty<unknown>(nodeDescriptor, 'value') === 'string'
    ? proc
    : undefined;
}

function claimNodeProcessWarning(apiName: string): boolean {
  if (warnedApis.has(apiName)) return false;
  try {
    const host = nodeWarningHost();
    if (host !== undefined) {
      const key = nodeProcessWarningKey(apiName);
      const marker = Object.getOwnPropertyDescriptor(host, key);
      if (marker !== undefined) return ownProperty<unknown>(marker, 'value') !== true;
      defineDataProperty(host, key, true, { enumerable: false, writable: false });
    }
  } catch {
    // An unavailable process slot leaves the existing per-module warning active.
  }
  return true;
}

/**
 * 環境変数による抑止が有効か。
 *
 * SDK はブラウザ向けにもバンドルされる（`bun build --target browser`）ため `process` が存在
 * しない実行環境がある。`globalThis` 経由で存在を確かめてから読むこと。`process.env` は
 * 汚染された `Object.prototype` から継承値を拾わないよう `ownProperty` で読む
 * （`Object.prototype.VERICERTS_...` を仕込まれて警告を黙らせられるのを防ぐ）。
 */
function isSuppressed(): boolean {
  const proc = ownProperty<unknown>(globalThis, 'process');
  if (typeof proc !== 'object' || proc === null) {
    return false;
  }
  const env = ownProperty<unknown>(proc, 'env');
  if (typeof env !== 'object' || env === null) {
    return false;
  }
  const value = ownProperty<unknown>(env, SUPPRESS_EXPERIMENTAL_WARNINGS_ENV);
  return value === '1' || value === 'true';
}

/**
 * `apiName` の `@experimental` 警告をプロセス内で 1 回だけ出す。
 *
 * 2 回目以降の呼び出しは何もしない。別の `apiName` は別に 1 回出る。
 *
 * @param apiName 公開 API 名（利用者が import する識別子）。
 * @param bestEffort 抑止設定の読み取りや警告出力が失敗しても呼び出しを続ける。
 * @internal
 */
export function warnExperimentalOnce(apiName: string, bestEffort = false): void {
  warnOnce(
    apiName,
    `[vericerts-wallet-sdk] \`${apiName}\` is @experimental: its behaviour and signature may change in a minor release. Set ${SUPPRESS_EXPERIMENTAL_WARNINGS_ENV}=1 to silence this warning.`,
    bestEffort,
  );
}

/**
 * `apiName` の `@deprecated` 警告をプロセス内で 1 回だけ出す。
 *
 * `warnExperimentalOnce` と同じ `Set` を共有するため、同じ API 名について両方が出ることはない
 * （成熟度は `@experimental` → `@deprecated` の一本道で、同時に両方のタグを持つ API は無い）。
 *
 * @param apiName 公開 API 名（利用者が import する識別子）。
 * @param replacement 代替 API を案内する文（例:「Use \`Wallet.receiveCredential\` instead.」）。
 * @internal
 */
export function warnDeprecatedOnce(apiName: string, replacement: string): void {
  warnOnce(
    apiName,
    `[vericerts-wallet-sdk] \`${apiName}\` is @deprecated: ${replacement} Set ${SUPPRESS_EXPERIMENTAL_WARNINGS_ENV}=1 to silence this warning.`,
  );
}

/** `apiName` について `message` をプロセス内で 1 回だけ `console.warn` する共通実装。 */
function warnOnce(apiName: string, message: string, bestEffort = false): void {
  if (warnedApis.has(apiName)) {
    return;
  }
  warnedApis.add(apiName);
  if (bestEffort) {
    warnBestEffort(message);
  } else if (!isSuppressed()) {
    console.warn(message);
  }
}

function warnBestEffort(message: string): void {
  try {
    if (isSuppressed()) return;
  } catch {
    // If environment access is denied, suppression is unconfirmed.
  }
  try {
    console.warn(message);
  } catch {
    // Diagnostic failure must not prevent the wrapped implementation from running.
  }
}

/** 警告記録を消す。テスト専用。 */
export function resetExperimentalWarnings(): void {
  warnedApis.clear();
  if (nodeProcessWarningApis.size === 0) return;
  const host = nodeWarningHost();
  if (host === undefined) return;
  for (const apiName of nodeProcessWarningApis) {
    const key = nodeProcessWarningKey(apiName);
    const marker = Object.getOwnPropertyDescriptor(host, key);
    if (marker !== undefined && ownProperty<unknown>(marker, 'value') === true) {
      Reflect.deleteProperty(host, key);
    }
  }
}

/** 呼び出し可能な公開 API（関数）。 */
type Callable = (...args: never[]) => unknown;

/** `new` できる公開 API（クラス）。 */
type Constructable = abstract new (...args: never[]) => unknown;

/**
 * 公開 API を `Proxy` の `apply` / `construct` トラップで包み、初回呼び出し / インスタンス化時に
 * `warn` を 1 回だけ実行する。**型 `T` がそのまま保たれる**（ジェネリック・オーバーロード・
 * 静的プロパティ・`instanceof`・`name` / `length` を失わない）。引数を受け直す素のラッパ関数だと
 * これらが落ちるので、ここでは `Proxy` を使う。`markExperimental` / `markDeprecated` の共通実装。
 */
function wrapWithWarning<T extends Callable | Constructable>(impl: T, warn: () => void): T {
  return new Proxy(impl, {
    apply(target, thisArg, args): unknown {
      warn();
      return Reflect.apply(target as (...a: unknown[]) => unknown, thisArg, args);
    },
    construct(target, args, newTarget): object {
      warn();
      return Reflect.construct(target as new (...a: unknown[]) => object, args, newTarget);
    },
  }) as T;
}

/**
 * 公開 API を `@experimental` 警告付きでラップする。
 *
 * @param apiName 公開 API 名（警告に出す識別子）。
 * @param impl ラップ対象の関数またはクラス。
 * @param scope `node-process` を指定すると同じ Node process オブジェクトを使う ESM/CJS で警告を共有する。
 * @returns `impl` と同じ型のラッパ。最初の呼び出し / インスタンス化で 1 回だけ警告する。
 * @internal
 */
export function markExperimental<T extends Callable | Constructable>(
  apiName: string,
  impl: T,
  scope?: 'node-process',
): T {
  if (scope === 'node-process') nodeProcessWarningApis.add(apiName);
  return wrapWithWarning(impl, () => {
    if (scope === 'node-process' && !claimNodeProcessWarning(apiName)) return;
    warnExperimentalOnce(apiName, scope === 'node-process');
  });
}

/**
 * 公開 API を `@deprecated` 警告付きでラップする。
 *
 * @param apiName 公開 API 名（警告に出す識別子）。
 * @param impl ラップ対象の関数またはクラス。
 * @param replacement 代替 API を案内する文。
 * @returns `impl` と同じ型のラッパ。最初の呼び出し / インスタンス化で 1 回だけ警告する。
 * @internal
 */
export function markDeprecated<T extends Callable | Constructable>(
  apiName: string,
  impl: T,
  replacement: string,
): T {
  return wrapWithWarning(impl, () => warnDeprecatedOnce(apiName, replacement));
}
