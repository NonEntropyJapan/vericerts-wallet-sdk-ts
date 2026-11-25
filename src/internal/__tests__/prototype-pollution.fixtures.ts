/**
 * `Object.prototype` 汚染下での挙動を検証するための共有ヘルパー。
 *
 * SDK の任意プロパティ読み取りが `Object.hasOwn` / `ownProperty` に限定されていることを、
 * 「その任意プロパティを**省略した**正当な呼び出し」に対して継承値が漏れ込まないかで検証する。
 *
 * 汚染は**非列挙**（`enumerable: false`）で仕込む。実際の prototype pollution 攻撃でも
 * `Object.defineProperty` 経由なら非列挙にできるうえ、列挙可能にするとテストプロセス内の
 * 無関係な `for...in` / スプレッドまで壊れて検証したい経路がぼやけるため。
 * `obj.prop` / `'prop' in obj` / 分割代入 / `??` はいずれも列挙可否に関わらず継承値を拾うので、
 * 非列挙でも本来検証したい欠陥はそのまま再現する。
 */

/** 任意の記述子で汚染し、必ず戻すための復元関数を返す（`finally` で削除する）。 */
function polluteWithDescriptors(
  descriptors: Readonly<Record<string, PropertyDescriptor>>,
): () => void {
  const proto = Object.prototype as unknown as Record<string, unknown>;
  const keys = Object.keys(descriptors);
  for (const key of keys) {
    if (Object.hasOwn(proto, key)) {
      throw new Error(`prototype pollution fixture would clobber Object.prototype.${key}`);
    }
    Object.defineProperty(proto, key, descriptors[key] as PropertyDescriptor);
  }
  return () => {
    for (const key of keys) {
      delete proto[key];
    }
  };
}

/** 汚染したキーを必ず戻すため、`finally` で削除する（データプロパティ形式）。 */
function pollute(props: Readonly<Record<string, unknown>>): () => void {
  const descriptors: Record<string, PropertyDescriptor> = {};
  for (const key of Object.keys(props)) {
    descriptors[key] = { value: props[key], writable: true, configurable: true, enumerable: false };
  }
  return polluteWithDescriptors(descriptors);
}

/**
 * `Object.prototype` を汚染した状態で同期処理を実行し、必ず元へ戻す。
 *
 * @param props 仕込むプロパティ（キー → 汚染値）。
 * @param fn 汚染下で実行する処理。
 * @returns `fn` の戻り値。
 */
export function withPollutedPrototype<T>(props: Readonly<Record<string, unknown>>, fn: () => T): T {
  const restore = pollute(props);
  try {
    return fn();
  } finally {
    restore();
  }
}

/**
 * `Object.prototype` を汚染した状態で非同期処理を実行し、必ず元へ戻す。
 *
 * @param props 仕込むプロパティ（キー → 汚染値）。
 * @param fn 汚染下で実行する処理。
 * @returns `fn` の解決値。
 */
export async function withPollutedPrototypeAsync<T>(
  props: Readonly<Record<string, unknown>>,
  fn: () => Promise<T>,
): Promise<T> {
  const restore = pollute(props);
  try {
    return await fn();
  } finally {
    restore();
  }
}

/**
 * `Object.prototype` を**アクセサ（getter）形式**で汚染した状態で同期処理を実行し、必ず元へ戻す。
 *
 * `withPollutedPrototype` はデータプロパティ（`{ value }`）固定であり、
 * 「汚染値と `Object.prototype.x` を同一性比較して除外する」実装はデータ汚染だけを塞ぐ。
 * getter は呼ばれるたびに**新しい値（例: 新しい関数インスタンス）**を返せるため、同一性比較は
 * 一致せず素通りする。この非対称性を突く回帰テストのために getter 形式を仕込めるようにする。
 *
 * @param getters 仕込むプロパティ（キー → 呼ばれるたびに汚染値を返す getter）。
 * @param fn 汚染下で実行する処理。
 * @returns `fn` の戻り値。
 */
export function withPollutedPrototypeAccessor<T>(
  getters: Readonly<Record<string, () => unknown>>,
  fn: () => T,
): T {
  const descriptors: Record<string, PropertyDescriptor> = {};
  for (const key of Object.keys(getters)) {
    descriptors[key] = { get: getters[key], configurable: true, enumerable: false };
  }
  const restore = polluteWithDescriptors(descriptors);
  try {
    return fn();
  } finally {
    restore();
  }
}

/**
 * `Object.prototype` を**アクセサ（getter）形式**で汚染した状態で非同期処理を実行し、必ず元へ戻す。
 *
 * `withPollutedPrototypeAccessor` の非同期版。汚染を仕込んだまま `await` する必要がある経路
 * （DI した `fetcher` / `NonceStore` を介する非同期検証など）で使う。同期版を非同期処理へ
 * 使うと、`fn` が返した Promise の解決前に `finally` が汚染を戻してしまい、検証したい経路が
 * 汚染下で走らない（テストがトートロジーになる）。
 *
 * @param getters 仕込むプロパティ（キー → 呼ばれるたびに汚染値を返す getter）。
 * @param fn 汚染下で実行する処理。
 * @returns `fn` の解決値。
 */
export async function withPollutedPrototypeAccessorAsync<T>(
  getters: Readonly<Record<string, () => unknown>>,
  fn: () => Promise<T>,
): Promise<T> {
  const descriptors: Record<string, PropertyDescriptor> = {};
  for (const key of Object.keys(getters)) {
    descriptors[key] = { get: getters[key], configurable: true, enumerable: false };
  }
  const restore = polluteWithDescriptors(descriptors);
  try {
    return await fn();
  } finally {
    restore();
  }
}

/**
 * `Object.prototype` を汚染し、**解除の時点を呼び出し側に委ねる**（データプロパティ形式）。
 *
 * `withPollutedPrototype` は `fn` を抜ける時点で必ず解除するため、「ある同期区間の**途中**で
 * 汚染が始まり、その区間を抜けた後で解除する」状況を作れない。区間途中の汚染に耐えるかを
 * 検証する回帰テスト（`hdkey-option-guard.ts` の記述子復元など）でのみ使うこと。
 *
 * @param props 仕込むプロパティ（キー → 汚染値）。
 * @returns 汚染を取り除く関数。呼び出し側が `finally` で**必ず**呼ぶこと。
 */
export function pollutePrototype(props: Readonly<Record<string, unknown>>): () => void {
  return pollute(props);
}
