/**
 * `DEBUG=vericerts:*` 名前空間パターン。
 *
 * Node.js の `debug` パッケージが実装している慣習（環境変数 `DEBUG` にカンマ／空白区切りで
 * パターンを並べ、`*` をワイルドカード、`-` 接頭辞を除外として扱う）を、追加の依存を増やさず
 * 同等の挙動として再実装したもの。SDK は「未注入時は no-op」の方針を
 * 取っているため、ロガー実装そのものにも npm パッケージを追加しない。
 *
 * ブラウザ向けビルド（`--target browser`）では `process` が存在しないため、参照前に必ず
 * 存在確認する。ブラウザ実行時は常に無効（すべての debug ログを抑制）として扱う。
 */

/** 1 パターン（`vericerts:*` 等）を正規表現に変換する。 */
function patternToRegExp(pattern: string): RegExp {
  // `*` 以外の正規表現特殊文字をエスケープする。
  const escaped = pattern.trim().replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  // 末尾が `:*`（`vericerts:did:*` 等）の場合は、その名前空間自体（`vericerts:did`）にも
  // マッチさせる。これで、名前空間の直下とその子孫の両方のログを選択できる。
  const source = escaped.endsWith(':*')
    ? `${escaped.slice(0, -2)}(:.*)?`
    : escaped.replace(/\*/g, '.*');
  return new RegExp(`^${source}$`);
}

/** `DEBUG` 環境変数の値を、有効化パターンと除外パターン（`-` 接頭辞）に分ける。 */
function compilePatterns(spec: string): { include: RegExp[]; exclude: RegExp[] } {
  const include: RegExp[] = [];
  const exclude: RegExp[] = [];
  for (const raw of spec.split(/[\s,]+/).filter((entry) => entry.length > 0)) {
    if (raw.startsWith('-')) {
      exclude.push(patternToRegExp(raw.slice(1)));
    } else {
      include.push(patternToRegExp(raw));
    }
  }
  return { include, exclude };
}

/** ブラウザ等 `process.env` を持たない実行環境では `undefined` を返す。 */
function readDebugEnv(): string | undefined {
  if (typeof process === 'undefined' || typeof process.env !== 'object' || process.env === null) {
    return undefined;
  }
  return process.env.DEBUG;
}

/**
 * 指定した名前空間の debug ログが `DEBUG` 環境変数で有効化されているか判定する。
 *
 * `DEBUG` は呼び出しのたびに読む（値のキャッシュはしない）。プロセス起動後に環境変数が
 * 書き換わるケースはテスト以外ほぼ無いが、キャッシュを持たない方が単純で、テストでも
 * リセット処理が要らない。
 */
export function isDebugNamespaceEnabled(namespace: string): boolean {
  const spec = readDebugEnv();
  if (!spec) {
    return false;
  }
  const { include, exclude } = compilePatterns(spec);
  if (include.length === 0) {
    return false;
  }
  if (exclude.some((pattern) => pattern.test(namespace))) {
    return false;
  }
  return include.some((pattern) => pattern.test(namespace));
}
