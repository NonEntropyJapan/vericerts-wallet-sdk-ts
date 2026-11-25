// test/interop/lib/known-incompatible.mjs
//
// 既知の非互換ペアの扱い（`pairs.json` の `knownIncompatible` を読む）。
//
// 恒常的な非互換（実装間の仕様解釈の差で、SDK 側の方針として変えないもの）が Nightly を fail にし、
// 同じ理由の Issue が起票され続けるのを防ぐ。ただし「記録した非互換が変わった」ことは検知し続ける。
//
//   - 登録ペアが fail し、かつ失敗理由が登録済みの文言を含む → `known-incompatible`
//     （run-peer-matrix の終了コードを失敗にせず、Issue 自動起票の対象にもならない）
//   - 登録ペアが pass した → `fail`（`unexpected-pass:`。非互換が解消した可能性があり、登録の見直しが要る）
//   - 登録ペアが登録外の理由で fail した → `fail` のまま（新しい壊れ方。登録を黙って素通りさせない）
//   - 登録外のペア → 変更しない（新しく落ちたペアは従来どおり fail）
//
// 登録の形: `{ pair, reasonIncludes, note }`
//   - pair: 公開互換テストのペア ID (`interop:<issuer>:<verifier>`)
//   - issue: 呼び出し側が任意で付ける従来形式の番号（正の整数）
//   - reasonIncludes: 失敗理由に含まれるべき文言（部分一致）。空文字は全理由に一致してしまうため不可
//   - note: 非互換の内容（人間可読。レポートの理由欄に載る）

/** 既知の非互換として扱った結果の status。 */
export const KNOWN_INCOMPATIBLE = 'known-incompatible';

/**
 * 登録 1 件の形式を確かめる。不正な登録は黙って無視せず、設定ミスとして即座に例外にする
 * （typo の登録が「どのペアにも一致しない」まま既知の非互換を fail に戻してしまうのを避ける）。
 */
function assertEntry(entry) {
  const fields = ['pair', 'reasonIncludes', 'note'];
  for (const field of fields) {
    if (typeof entry?.[field] !== 'string' || entry[field] === '') {
      throw new Error(
        `knownIncompatible: ${field} は空でない文字列が必要 (${JSON.stringify(entry)})`,
      );
    }
  }
  if ('issue' in entry && (!Number.isInteger(entry.issue) || entry.issue <= 0)) {
    throw new Error(`knownIncompatible: issue は正の整数が必要 (${entry.pair})`);
  }
}

/**
 * マトリクス結果に既知の非互換の登録を適用する。
 *
 * @param results `run-peer-matrix.mjs` が組み立てた PairResult の配列。
 * @param entries `pairs.json` の `knownIncompatible`（省略時は何も変えない）。
 * @returns 適用後の PairResult 配列（入力は変更しない）。
 * @throws 登録の形式が不正、または同じペアが二重に登録されている場合。
 */
export function applyKnownIncompatible(results, entries = []) {
  const byPair = new Map();
  for (const entry of entries) {
    assertEntry(entry);
    if (byPair.has(entry.pair)) {
      throw new Error(`knownIncompatible: ${entry.pair} が二重に登録されている`);
    }
    byPair.set(entry.pair, entry);
  }

  return results.map((result) => {
    const entry = byPair.get(result.pair);
    if (!entry) {
      return result;
    }
    const reference = 'issue' in entry ? `#${entry.issue}` : `[${entry.pair}]`;
    if (result.status === 'pass') {
      return {
        pair: result.pair,
        status: 'fail',
        reason: `unexpected-pass: 既知の非互換（${reference}: ${entry.note}）のペアが通った。非互換が解消した可能性があるため、pairs.json の knownIncompatible から外すか理由を見直す`,
      };
    }
    if (result.status === 'fail' && String(result.reason ?? '').includes(entry.reasonIncludes)) {
      return {
        pair: result.pair,
        status: KNOWN_INCOMPATIBLE,
        reason: `${reference} ${entry.note} — ${result.reason}`,
      };
    }
    return result;
  });
}
