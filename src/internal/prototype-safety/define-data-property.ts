/**
 * `Object.defineProperty` へ渡す**記述子自身**のプロトタイプ汚染を塞ぐヘルパー。
 *
 * ## 何を防ぐか
 *
 * `Object.defineProperty(target, key, { value, writable: true, … })` の第 3 引数は
 * **オブジェクトリテラル**なので `Object.prototype` を継承する。したがって
 * `Object.prototype.get`（または `.set`）が関数で汚染された環境では、その記述子が
 * 「`value` と `get` の両方を持つ」と解釈され、`Object.defineProperty` が
 *
 * ```text
 * TypeError: Invalid property. 'value' present on property with getter or setter.
 * ```
 *
 * を**必ず**投げる。データプロパティを 1 つ定義するだけの処理が、汚染されたプロセスでは
 * 全件失敗する。本 SDK ではこれが可用性の問題に留まらない:
 *
 * - `deep-snapshot.ts` の畳み込み、`identity/normalized-log-input.ts` /
 *   `issuer/module/normalized-issue-input.ts` の正規化スナップショットが例外で中断し、
 *   **攻撃者制御の生の `TypeError` が公開 API まで抜ける**（契約内のエラーコードにならない）。
 * - `credential/sdjwt/claims.ts` の `recoverClaims` と `sdjwt.ts` / `gdpr-guard.ts` の
 *   クレーム設定（`__proto__` 対策として `defineProperty` を選んだ箇所）も同じ経路で
 *   落ちるため、**`__proto__` 対策のために導入した手段そのものが新しい停止経路になっていた**。
 *
 * ## 対策
 *
 * 記述子を `Object.create(null)` で作る。プロトタイプを持たないので `get` / `set` を継承しえず、
 * 汚染の有無に関わらず**純粋なデータ記述子**として解釈される。
 *
 * `Object.defineProperty` を直接呼ぶ代わりに本ヘルパーを使うこと。**記述子リテラルを直接渡す形へ
 * 戻してはならない**（`internal/prototype-safety/parse-json.ts` の「既存の `ownProperty` 呼び出しを削っては
 * ならない」と同じ位置づけの規約である）。
 *
 * @module
 */

/** {@link defineDataProperty} で指定するプロパティ属性（すべて既定 `true`）。 */
export interface DataPropertyFlags {
  /** 書き換え可能か（既定 `true`）。 */
  readonly writable?: boolean;
  /** 列挙可能か（既定 `true`）。 */
  readonly enumerable?: boolean;
  /** 再定義・削除可能か（既定 `true`）。 */
  readonly configurable?: boolean;
}

/**
 * `target` に own データプロパティを定義する（記述子は `null` プロトタイプで作る）。
 *
 * `key` が `__proto__` でも**通常の own データプロパティ**になる（`Object.defineProperty` の
 * 意味論。生代入 `target[key] = value` だと継承した `__proto__` setter が発火して
 * プロパティが消え、`target` のプロトタイプが差し替わる）。
 *
 * @param target 定義先のオブジェクト。
 * @param key プロパティ名（`string` / `symbol`）。
 * @param value プロパティ値。
 * @param flags プロパティ属性。省略したメンバは `true`。
 */
export function defineDataProperty(
  target: object,
  key: string | symbol,
  value: unknown,
  flags: DataPropertyFlags = {},
): void {
  // 記述子はプロトタイプなしで組む。リテラル `{ … }` だと `Object.prototype.get` / `.set` の
  // 汚染で「アクセサと value の同時指定」と解釈され `defineProperty` が TypeError を投げる。
  const descriptor = Object.create(null) as {
    value: unknown;
    writable: boolean;
    enumerable: boolean;
    configurable: boolean;
  };
  descriptor.value = value;
  // `flags` は呼び出し側のリテラルなので own 限定で読む（未指定は既定 `true`）。
  descriptor.writable = Object.hasOwn(flags, 'writable') ? flags.writable !== false : true;
  descriptor.enumerable = Object.hasOwn(flags, 'enumerable') ? flags.enumerable !== false : true;
  descriptor.configurable = Object.hasOwn(flags, 'configurable')
    ? flags.configurable !== false
    : true;
  Object.defineProperty(target, key, descriptor);
}

/**
 * `Object.getOwnPropertyDescriptor` で取得した記述子を、プロトタイプなしの複製へ写す。
 *
 * エンジンが返す記述子も `Object.prototype` を継承する通常のオブジェクトなので、そのまま
 * `Object.defineProperty` へ渡すと汚染下で `TypeError` になる（データ記述子に継承 `get` が
 * 見えるため）。退避した記述子をそのまま復元する `keymanager/hardening/hdkey-option-guard.ts`
 * のような用途で使う。
 *
 * @param descriptor 写す記述子（own メンバだけを写す）。
 * @returns `null` プロトタイプの複製。
 */
export function toBareDescriptor(descriptor: PropertyDescriptor): PropertyDescriptor {
  const bare = Object.create(null) as Record<string, unknown>;
  for (const key of Object.getOwnPropertyNames(descriptor)) {
    bare[key] = (descriptor as Record<string, unknown>)[key];
  }
  return bare as PropertyDescriptor;
}
