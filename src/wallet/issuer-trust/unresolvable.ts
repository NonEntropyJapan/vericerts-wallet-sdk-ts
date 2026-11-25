/**
 * 受領した VC の Issuer 鍵解決に失敗したことを表す内部例外。
 *
 * 解決経路は複数ある（`x5c.ts` の証明書チェーン、`jwt-vc-issuer.ts` の JWT VC Issuer Metadata、
 * `setup.ts` の DID 解決）が、**どの経路のどの段で落ちたかを呼び出し側へ伝えない**のが規約である。
 * 理由コードへの正規化は分岐の外側（`received-signature.ts` の `issuerKeyUnresolved`、
 * `3010` / `issuer_key_unresolved`）が 1 箇所で行う — 経路ごとに理由を分けると「どの経路まで
 * 進んだか」が攻撃者への観測チャネルになり、かつ呼び出し側が経路ごとの分岐を書くことになる。
 *
 * 各経路のファイルで同じ関数を持つと、片方だけ `context` を足す・別コードへ変える改変が起きて
 * この規約が崩れるため、**経路から独立した leaf モジュール**として 1 箇所に置く。ここが leaf
 * （`errors.js` 以外に依存しない）なのは、経路モジュールと分岐ディスパッチャ（`resolve.ts`）の
 * 双方から参照されても循環 import にならないようにするためである。
 */

import { ErrorCodes, VericertsError } from '../../internal/errors.js';

/**
 * 鍵解決に失敗したことを表す内部例外を作る。
 *
 * `context` は付けない（付けると経路ごとの失敗理由が呼び出し側へ漏れる。上記参照）。
 */
export function unresolvable(): VericertsError {
  return new VericertsError(ErrorCodes.SIG_INVALID);
}
