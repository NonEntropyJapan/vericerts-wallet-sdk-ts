/**
 * DID 解決スコープの予算を「全 DID メソッドの解決経路で必ず通る共通の入口」で計上する。
 *
 * ## なぜ共通の入口か
 *
 * did:web・did:webvh の取得経路が**それぞれ**予算を呼ぶ形で縛った。
 * そのため `scope` を受け取らない did:ipid / did:ethr は予算の外に残り、相異なる DID を 32 件並べると
 * 1 件ごとの上限が総量の上限にならなかった（1 MiB × 32 = RSS 1 GB、990 イベント × 32 = CPU 4 秒）。
 * メソッドごとに「呼び忘れない」ことに頼る構造では、新しいメソッドを足すたびに同じ欠陥が再発する。
 *
 * `createBoundedResolver` は解決を {@link resolveWithinScope} 越しにしか下位 resolver へ渡さない。
 * 下位メソッドが何を計上したか（あるいは何も計上しなかったか）に関わらず、**返した DID Document が
 * スコープの間保持する量**は戻り値の時点で必ず本文量予算から引かれる。メソッド側は、パース・デコードの
 * **前**に拒否したい取得（本文・イベント）だけ `consumeResolutionBody` / `consumeResolutionWork` を呼ぶ。
 * 両者で同じ本文を二重に数えないよう、メソッドが計上した本文量は戻り値の保持量から差し引く。
 *
 * 計上は決定的な量（文字数の見積もり・件数）で行い、テストは実時間ではなくカウンタ・例外種別で pin できる。
 *
 * セキュリティ上の注意: 例外の `context` に DID 文字列を含めない（resolver.ts 冒頭と同じ制約）。
 */

import type { DIDDocument } from './did.js';
import { consumeResolutionBody, type ResolutionWorkBudget } from './resolution-budget.js';

/** 文字列 1 つを JSON にしたときの引用符ぶん。 */
const STRING_QUOTES_LENGTH = 2;
/** オブジェクトのメンバー 1 つの区切り（`"":` と `,`）ぶん。 */
const MEMBER_OVERHEAD_LENGTH = 4;
/** 配列要素 1 つの区切り（`,`）ぶん。 */
const ELEMENT_OVERHEAD_LENGTH = 1;
/** `{}` / `[]` の括弧ぶん。 */
const CONTAINER_OVERHEAD_LENGTH = 2;
/** 数値・真偽値・null の見積もり長（最短の `1`。過大に数えて正規の文書を弾かないため下限にとる）。 */
const SCALAR_LENGTH = 1;

/**
 * 値を JSON にした場合の文字数を、文字列化せずに見積もる（循環・巨大入力でも `cap` で打ち切る）。
 *
 * 文字列長・キー長・要素数・入れ子の括弧を数える決定的な概算で、コンパクトな `JSON.stringify` 長を
 * **超えない**（数値・真偽値・null は最短の 1 文字で数える）。`cap` を超えた時点で歩行を止め、`cap + 1` 以上の値を返す
 * （予算より大きい構造を全部なめるコストを払わない）。
 *
 * @param value 見積もる値（`JSON.parse` 由来の構造を想定）。
 * @param cap 打ち切る上限。
 * @returns 見積もり文字数。`cap` を超えるなら `cap + 1` 以上。
 */
export function estimateJsonLength(value: unknown, cap: number): number {
  let total = 0;
  const pending: unknown[] = [value];
  while (pending.length > 0 && total <= cap) {
    const current = pending.pop();
    if (typeof current === 'string') {
      total += current.length + STRING_QUOTES_LENGTH;
    } else if (typeof current === 'number' || typeof current === 'boolean' || current === null) {
      total += SCALAR_LENGTH;
    } else if (Array.isArray(current)) {
      // 末尾要素の後ろには区切りが無いので 1 つ引く（コンパクトな JSON 本文長を超えて数えない）。
      total +=
        CONTAINER_OVERHEAD_LENGTH + Math.max(0, current.length * ELEMENT_OVERHEAD_LENGTH - 1);
      for (const element of current) {
        pending.push(element);
      }
    } else if (typeof current === 'object') {
      const keys = Object.keys(current);
      total += CONTAINER_OVERHEAD_LENGTH + Math.max(0, keys.length * MEMBER_OVERHEAD_LENGTH - 1);
      for (const key of keys) {
        total += key.length;
        pending.push((current as Record<string, unknown>)[key]);
      }
    }
  }
  return total;
}

/**
 * 値の保持量（{@link estimateJsonLength}）を本文量として消費する。`budget` が無い呼び出しは計上しない。
 * 取得したイベント・ログ配列のように、パース済みでデコード前の値をデコードより前に拒否したい経路が使う。
 *
 * @param alreadyConsumed この値の本文として既に消費済みの量（二重に数えない）。
 * @throws 残りが足りない場合（VericertsError、code `2001`、`context.reason: 'resolution_work_limit'`）。
 */
export function consumeResolutionValue(
  budget: ResolutionWorkBudget | undefined,
  value: unknown,
  alreadyConsumed = 0,
): void {
  if (budget === undefined) {
    return;
  }
  const retained = estimateJsonLength(value, alreadyConsumed + budget.remainingBodyLength);
  consumeResolutionBody(budget, Math.max(0, retained - alreadyConsumed));
}

/**
 * 1 回の解決の間に本文量として消費された量を数える**ビュー**。予算本体の読み書きはそのまま通し、
 * `remainingBodyLength` が減った分だけを記録する（並行する別の解決の消費は混ざらない）。
 */
function trackBodyConsumption(shared: ResolutionWorkBudget): {
  readonly view: ResolutionWorkBudget;
  readonly consumed: () => number;
} {
  let consumed = 0;
  const view: ResolutionWorkBudget = {
    get remaining() {
      return shared.remaining;
    },
    set remaining(value: number) {
      shared.remaining = value;
    },
    get remainingBodyLength() {
      return shared.remainingBodyLength;
    },
    set remainingBodyLength(value: number) {
      consumed += Math.max(0, shared.remainingBodyLength - value);
      shared.remainingBodyLength = value;
    },
  };
  return { view, consumed: () => consumed };
}

/** 1 回の試行が消費した仕事量・本文量（{@link trackAttempt}）。 */
export interface AttemptWork {
  units: number;
  body: number;
}

/**
 * 取り直しを伴う解決の**試行 1 回**が消費する仕事量・本文量を数え、前の試行（捨てた試行）が既に計上した分を**控除枠**として
 * 引き継ぐ**ビュー**（内部用）。
 *
 * 取り直し（拡張の in-flight 予算が追加確保できなかったときの 1 回目の破棄。`webvh/resolve.ts` の `beforeWitnessFile`）で、
 * 1 回目の消費を 2 回目へ持ち越して二重に計上すると、予算ぎりぎりの正規の解決が競合のときだけ `2001` になる。かといって
 * 1 回目を全額差し戻すと、1 回目に最大の仕事（512 版の署名検証）をさせて破棄し、2 回目を安く失敗させる繰り返しで、予算が
 * 減らないまま実作業だけが積み上がる。そこで 1 回目の計上は**そのまま残し**、
 * 2 回目の消費を、まず前の試行の計上分（`prior`）で相殺する: 2 回目が `d` を消費すると、残っている控除枠から `min(枠, d)` を
 * 引いてその分は予算本体へ課金せず、超えた分だけを課金する。結果、1 つの解決が予算へ課金する合計は
 * `max(1 回目, 2 回目)` になる（2 回目が正規に 1 回目と同じ量を使えば追加の課金は 0、2 回目が安く失敗すれば 1 回目の計上が
 * 残る）。実作業は計上額の高々 2 倍（1 回目 + 2 回目 ≤ 2 × max）。
 *
 * 予算本体には、自分の課金（控除枠で相殺されなかった分）しか書かない。スナップショットの復元も差し戻しも無いので、同じ予算を
 * 並行して使う別の解決の消費は変わらず、残りが負になることも元の上限を超えることもない。ビューの `remaining` /
 * `remainingBodyLength` は、本体の残りに控除枠を足した値を返す（控除枠で足りる消費を、本体の残りが 0 でも拒否しない）。
 *
 * @param shared 予算本体（スコープ共通）。
 * @param prior 前の試行が既に課金した量。無ければ 0（控除なし）。
 * @returns 解決に渡すビューと、この試行が（相殺された分を含めて）消費した総量。
 */
export function trackAttempt(
  shared: ResolutionWorkBudget,
  prior: Readonly<AttemptWork>,
): {
  readonly view: ResolutionWorkBudget;
  readonly consumed: () => Readonly<AttemptWork>;
} {
  let creditUnits = Math.max(0, prior.units);
  let creditBody = Math.max(0, prior.body);
  const used: AttemptWork = { units: 0, body: 0 };
  const view: ResolutionWorkBudget = {
    get remaining() {
      return shared.remaining + creditUnits;
    },
    set remaining(value: number) {
      const delta = shared.remaining + creditUnits - value;
      if (delta > 0) {
        const absorbed = Math.min(creditUnits, delta);
        creditUnits -= absorbed;
        used.units += delta;
        shared.remaining -= delta - absorbed;
      } else {
        shared.remaining -= delta;
      }
    },
    get remainingBodyLength() {
      return shared.remainingBodyLength + creditBody;
    },
    set remainingBodyLength(value: number) {
      const delta = shared.remainingBodyLength + creditBody - value;
      if (delta > 0) {
        const absorbed = Math.min(creditBody, delta);
        creditBody -= absorbed;
        used.body += delta;
        shared.remainingBodyLength -= delta - absorbed;
      } else {
        shared.remainingBodyLength -= delta;
      }
    },
  };
  return { view, consumed: () => used };
}

/**
 * 下位 resolver の 1 回の解決をスコープ予算つきで実行し、返した DID Document の保持量を計上する。
 *
 * `createBoundedResolver` が下位の `resolve` を呼ぶ**唯一の入口**。メソッドが内部で本文量を計上したかに
 * 関わらず、戻り値（スコープの間 `resolutions` に保持される文書）の見積もり長から、メソッド自身が
 * 計上した分を引いた残りをここで消費する。全メソッド（did:key / jwk / pkh / peer / jwt / web / webvh /
 * ipid / ethr）が同じ経路を通る。
 *
 * @param shared スコープ共通の予算。
 * @param resolve 予算（ビュー）を受け取って解決する関数。
 * @returns 解決済みの DID Document。
 * @throws 保持量が残りの本文量を超える場合（VericertsError、code `2001`、`resolution_work_limit`）。
 */
export async function resolveWithinScope(
  shared: ResolutionWorkBudget,
  resolve: (scope: ResolutionWorkBudget) => Promise<DIDDocument>,
): Promise<DIDDocument> {
  const { view, consumed } = trackBodyConsumption(shared);
  const document = await resolve(view);
  consumeResolutionValue(shared, document, consumed());
  return document;
}
