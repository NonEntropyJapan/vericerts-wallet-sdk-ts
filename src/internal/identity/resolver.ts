/**
 * DID メソッドプラグインを束ねる Resolver。
 *
 * 登録された `DIDMethod` から DID 文字列のメソッド部
 * （`did:<method>:...` の `<method>`）に一致するものを選び、解決を委譲する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列を含めない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import type { DIDDocument, DIDMethod, UpdateOptions } from './did.js';
import { extractDidMethod, isDidWithinLengthLimit } from './did-format.js';
import type { ResolutionWorkBudget } from './resolution-budget.js';

/**
 * 登録済み `DIDMethod` への解決ディスパッチを行う Resolver。
 */
export class Resolver {
  /** メソッド名 → プラグインの登録テーブル。 */
  private readonly methods = new Map<string, DIDMethod>();
  /**
   * メソッド名 → 「キャッシュなし」の解決用プラグイン（{@link registerUncached}）。署名のたびに最新の DID Document で鍵を
   * 照合する経路（{@link resolveUncached}）だけが使う。
   */
  private readonly uncachedMethods = new Map<string, DIDMethod>();

  /**
   * DID メソッドプラグインを登録する。同名メソッドは上書きする。
   *
   * 同名の「キャッシュなし」版（{@link registerUncached}）は破棄する。呼び出し側が差し替えたプラグインを
   * {@link resolveUncached} も迂回せずそのまま使うためで（キャッシュの有無はそのプラグインの責務）、元の組み込み版の
   * キャッシュなし版が残って差し替えを無視する、ということが起きない。
   *
   * @param method 登録する DID メソッドプラグイン。
   */
  register(method: DIDMethod): void {
    this.methods.set(method.method(), method);
    this.uncachedMethods.delete(method.method());
  }

  /**
   * 同名メソッドの「キャッシュなし」版を登録する（{@link resolveUncached} だけが使う）。解決結果を記憶するメソッド
   * （did:web / did:ebsi / did:ion / did:cheqd）に、記憶しない版を添えるのに使う。`register` より後に呼ぶこと
   * （`register` は同名の版を破棄する）。
   *
   * @param method キャッシュを持たない DID メソッドプラグイン。
   */
  registerUncached(method: DIDMethod): void {
    this.uncachedMethods.set(method.method(), method);
  }

  /**
   * DID 文字列を DID Document に解決する。
   *
   * @param did DID 文字列（`did:<method>:<identifier>`）。
   * @param scope 解決スコープ全体の仕事量予算（`createBoundedResolver` が渡す）。
   * @returns DID Document。
   * @throws DID 形式違反の場合（VericertsError、code `2001`）、
   *         未登録メソッドの場合（VericertsError、code `2002`）。
   */
  async resolve(did: string, scope?: ResolutionWorkBudget): Promise<DIDDocument> {
    return this.methodOf(did).resolve(did, scope);
  }

  /**
   * {@link resolve} と同じだが、「キャッシュなし」版（{@link registerUncached}）があるメソッドはそれで解決する
   * （無いメソッドは通常の登録プラグイン。did:key など決定的な解決や、キャッシュを持たない did:plc / did:webvh /
   * did:ipid / did:ethr、`register` で差し替えられたプラグインがそれに当たる）。
   *
   * 鍵のローテーション・削除が直ちに効かなければならない経路（取り込んだ DID のペルソナの署名・取り込み）が使う。
   *
   * @param did DID 文字列。
   * @param scope 解決スコープ全体の仕事量予算。
   * @returns DID Document。
   * @throws {@link resolve} と同じ。
   */
  async resolveUncached(did: string, scope?: ResolutionWorkBudget): Promise<DIDDocument> {
    return this.methodOf(did, this.uncachedMethods).resolve(did, scope);
  }

  /**
   * DID 更新を登録済みプラグインへ委譲する。
   *
   * 差分の適用と GDPR Art.9 ガードは呼び出し側（`wallet/did/update.ts`）が済ませ、本メソッドは
   * `resolve` と同じ規則でプラグインを選ぶだけである。`methods` を公開せずディスパッチを
   * Resolver 側に置くのは、登録テーブルを外へ出すと `registerDIDMethod`で差し替えた
   * プラグインを呼び出し側が迂回できてしまうためである。
   *
   * @param did 更新対象の DID 文字列。
   * @param opts 更新オプション（適用済み Document を含む）。
   * @returns 公開後の DID Document。
   * @throws DID 形式違反の場合（VericertsError、code `2001`）、
   *         未登録メソッドの場合（code `2002`）。更新非対応のメソッドは `2002` を投げる。
   */
  async update(did: string, opts: UpdateOptions): Promise<DIDDocument> {
    return this.methodOf(did).update(did, opts);
  }

  /**
   * DID 文字列のメソッド部から登録済みプラグインを選ぶ。
   *
   * @param did DID 文字列（`did:<method>:<identifier>`）。
   * @returns 登録済みプラグイン。
   * @throws DID 形式違反の場合（VericertsError、code `2001`）、
   *         未登録メソッドの場合（code `2002`）。
   */
  private methodOf(did: string, preferred?: ReadonlyMap<string, DIDMethod>): DIDMethod {
    // 長さ上限は署名検証前の攻撃者制御入力に対する CPU 枯渇対策。
    const methodName = isDidWithinLengthLimit(did) ? extractDidMethod(did) : undefined;
    if (methodName === undefined) {
      // 入力 DID はメッセージに含めない。
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    const method = preferred?.get(methodName) ?? this.methods.get(methodName);
    if (method === undefined) {
      throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
    }
    return method;
  }
}
