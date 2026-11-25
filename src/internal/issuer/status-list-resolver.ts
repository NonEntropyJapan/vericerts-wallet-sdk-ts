/**
 * Token Status List 参照（`StatusReference`）を評価する解決器の実装。
 *
 * IETF draft-ietf-oauth-status-list に基づく。
 *
 * credential ドメインは `StatusListResolver` インターフェース（`sdjwt-status.ts`）の DI seam のみを
 * 持ち、実際のビット評価は issuer ドメインが供給する。本モジュールはその実装として、
 * 検証の流れ:
 *
 * 1. `status.status_list.uri` から Status List Token（JWT）を取得する（`fetchToken` で DI）。
 * 2. Issuer 公開鍵で JWT 署名を検証する（`alg=none` / 未対応 alg は拒否）。
 * 3. `sub` が参照 `uri` と一致することを確認する（confused deputy 対策）。
 * 4. `status_list.lst` を zlib 展開する。
 * 5. ビットインデックス `idx` の値を読み取る。
 * 6. 値が 0 なら有効、それ以外なら失効/停止（`StatusCheckResult`）。
 *
 * ## キャッシュ層
 *
 * `statusCache` を渡すと 1 が TTL キャッシュ経由になる（`Cache-Control: max-age` 尊重・上限 60 秒
 * キャップ・negative cache 30 秒固定・Token 自身の `exp` で切り詰め）。新規取得した Token が既に
 * `exp` を過ぎていれば `VC_EXPIRED`（3024）で拒否する。判断は
 * `status-list-cache.ts` に置き、本モジュールは検証フローへの配線だけを持つ。署名検証・`sub` 一致
 * 確認（2 と 3）はキャッシュ命中時もやり直すため、キャッシュに入った時点で検証済みとは扱わない。
 *
 * ## Fail-open（FO-1 / FO-2）
 *
 * 1 の取得に失敗した場合のみ Fail-open を選択できる。取得失敗時にキャッシュ済みの
 * stale な Token があるかどうかで、次の 2 事象を区別する:
 *
 * - stale な Token が**無い**（キャッシュ未配線・初回取得の失敗など）→ **FO-1**（Status List URL
 *   到達不能）。失効状態を一切確認できないため、既定に従い有効とみなして通過する。
 * - stale な Token が**有る**（TTL 切れ後の再取得に失敗）→ **FO-2**（staleness > TTL）。古いとはいえ
 *   実データがあるため、stale な Token を通常どおり検証してビット値を読み、**実際の失効状態**を
 *   返す。失効済み VC が Fail-open で有効に戻ることは無い。
 *
 * URI ごとの猶予期間内で、次の同意と監査記録の条件を満たせば続行できる。期間や条件を満たせない場合は元の取得エラーを送出する。
 *
 * - 同意手段: `requestConsent`（無ければ同意を取れない。`suppressPrompt` に該当 ID を挙げた場合のみ省略可）。
 * - 監査記録先として `onPolicyEvent` を指定する。
 *
 * Fail-closed へ戻したい場合は `failSafePolicy.escalate` に `FO-1` / `FO-2` を挙げる（opt-in）。
 * 署名検証・`sub` 一致・ビット読み取りでの失敗に Fail-open は適用しない。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に URL・インデックス・ビット値・JWT を含めない。
 * - 監査レコードにも同様に URI を含めない。`auditContext` は呼び出し側が用意した識別子を透過する。
 */

import { resolveMaxTtlSeconds, systemNowSeconds } from '../cache/index.js';
import type { StatusReference } from '../credential/sdjwt/sdjwt.js';
import type { StatusCheckResult, StatusListResolver } from '../credential/sdjwt/status.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import type { FailSafeWarning } from '../failsafe-policy/index.js';
import { createFailOpenWindow } from '../failsafe-policy/index.js';
import { nonObjectPrototypeProperty, ownProperty } from '../prototype-safety/own-property.js';
import {
  createStatusListFreshness,
  resolveMaxTokenAgeSeconds,
} from './freshness/status-list-freshness.js';
import {
  cacheFetchedToken,
  lookupCachedToken,
  normalizeTokenResponse,
  type StatusListCacheDeps,
  type StatusListTokenResponse,
} from './status-list-cache.js';
import { decideFetchFailure } from './status-list-fail-open.js';
import { countStatusListChecks, instrumentStatusListFetch } from './status-list-observability.js';
import type { StatusListResolverOptions } from './status-list-resolver-options.js';
import { readStatusBit, verifyStatusListToken } from './status-list-token-verify.js';
import { STATUS_VALUE_VALID } from './status-list-types.js';
import { DEFAULT_STATUS_CACHE_MAX_TTL_SECONDS } from './status-list-verifier.js';

export type { StatusListResolverOptions } from './status-list-resolver-options.js';

/**
 * Token Status List 参照を評価する `StatusListResolver` を生成する。
 *
 * 生成した解決器は credential ドメインの `resolveStatus` / SD-JWT 検証へ DI して使う。
 *
 * Fail-open の時間上限を数えるウィンドウは解決器インスタンスごとに持つ（`uri` 単位で計時し、
 * 取得に成功したら破棄して次の失敗を新しいウィンドウで評価する）。
 *
 * `maxTtlSeconds` の妥当性はキャッシュの有無に依らず**生成時**に検証する（効かない設定のまま
 * 運用に入るのを防ぐ）。
 *
 * @param opts fetchToken / issuerPublicKey / purpose と、任意のキャッシュ・fail-safe オプション。
 * @returns `StatusListResolver`。
 * @throws `failOpenMaxSeconds` / `maxTtlSeconds` が不正な場合（VericertsError、code `3002`）。
 *         `maxTtlSeconds` は 60 秒を超える緩和方向の指定も拒否する。
 */
export function createStatusListResolver(opts: StatusListResolverOptions): StatusListResolver {
  // 任意オプションは自身のプロパティに限って読む。継承値を拾うと、これらを
  // 指定していない正当な構築でも失効ステータスの鮮度判定が緩む:
  // - `nowSeconds`: キャッシュ TTL の評価が攻撃者の選んだ時刻で行われ、TTL 超過の
  //   失効ステータスがそのまま再利用される。
  // - `maxTtlSeconds` / `failOpenMaxSeconds`: キャッシュ上限と fail-open の時間上限が広がる。
  // - `statusCache`: 失効判定のキャッシュが攻撃者提供のストアへ委譲される。
  const failOpenWindow = createFailOpenWindow(ownProperty<number>(opts, 'failOpenMaxSeconds'));
  const maxTtlSeconds = resolveMaxTtlSeconds(
    ownProperty<number>(opts, 'maxTtlSeconds'),
    DEFAULT_STATUS_CACHE_MAX_TTL_SECONDS,
  );
  const now =
    ownProperty<StatusListResolverOptions['nowSeconds']>(opts, 'nowSeconds') ?? systemNowSeconds;
  // キャッシュ・取得関数・検証鍵・用途も own 限定で 1 度だけ読み、以降はこの値だけを使う。
  // 読み書きで読み方が食い違うと、読み取りは own（＝キャッシュ無し）なのに書き込みだけ
  // 汚染ストアへ流れる非対称が生じる。`issuerPublicKey` は Status List Token の**署名検証鍵**
  // なので、継承値を拾うと攻撃者の鍵で失効リストを検証してしまう。
  const statusCache = ownProperty<StatusListResolverOptions['statusCache']>(opts, 'statusCache');
  // 必須メンバは `Object.prototype` 由来だけを弾いて読む（`fetchToken` を prototype メソッドで
  // 公開する正当なクラスインスタンスを受理するため own 限定にはしない）。**構築時に**妥当性を
  // 検証する: 未検証のキャストのままだと、設定ミスや汚染で `fetchToken` が undefined になった
  // 場合に `resolve` 内の TypeError が取得失敗として捕捉され、fail-safe 設定時に FO-1 経由で
  // `{ valid: true }`（＝失効していない）へ洗浄されてしまう。`maxTtlSeconds` /
  // `failOpenMaxSeconds` を構築時に検証しているのと方針を揃える。
  const fetchToken = nonObjectPrototypeProperty<StatusListResolverOptions['fetchToken']>(
    opts,
    'fetchToken',
  );
  const issuerPublicKey = nonObjectPrototypeProperty<StatusListResolverOptions['issuerPublicKey']>(
    opts,
    'issuerPublicKey',
  );
  const purpose = nonObjectPrototypeProperty<StatusListResolverOptions['purpose']>(opts, 'purpose');
  if (
    typeof fetchToken !== 'function' ||
    issuerPublicKey === null ||
    typeof issuerPublicKey !== 'object' ||
    typeof purpose !== 'string'
  ) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const cacheDeps: StatusListCacheDeps = {
    cache: statusCache,
    onCacheEvent: ownProperty<StatusListResolverOptions['onCacheEvent']>(opts, 'onCacheEvent'),
  };
  const metrics = ownProperty<StatusListResolverOptions['metrics']>(opts, 'metrics');
  const freshness = createStatusListFreshness(
    resolveMaxTokenAgeSeconds(ownProperty<number>(opts, 'maxTokenAgeSeconds')),
  );

  const resolver: StatusListResolver = {
    async resolve(ref: StatusReference): Promise<StatusCheckResult> {
      // 参照先（取得する Token の URI と失効ビット位置）は own 限定で読み、型を確かめる。省略した `status_list` /
      // `idx` / `uri` が `Object.prototype` の汚染値を拾うと、攻撃者が選んだ URI の Status List で失効判定が行われる。
      const statusList = ownProperty<object>(ref, 'status_list');
      const idx = statusList === undefined ? undefined : ownProperty<unknown>(statusList, 'idx');
      const uri = statusList === undefined ? undefined : ownProperty<unknown>(statusList, 'uri');
      if (typeof idx !== 'number' || typeof uri !== 'string') {
        throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
      }
      const nowSeconds = now();
      // 取得レイテンシの計装は呼び出しごとに作る。キャッシュ参照と取得関数を包むだけで
      // 検証フローの制御は変えない（計器未注入なら素の依存がそのまま返る）。
      const probe = instrumentStatusListFetch(metrics, cacheDeps, fetchToken);

      const lookup = lookupCachedToken(uri, probe.deps, nowSeconds);
      let token = lookup.fresh;
      let fetched: StatusListTokenResponse | undefined;
      let warning: FailSafeWarning | undefined;

      if (token === undefined) {
        // negative cache が生きている間はネットワークに出ず、記憶した失敗をそのまま評価に回す。
        let fetchError = lookup.remembered;
        if (fetchError === undefined) {
          try {
            fetched = normalizeTokenResponse(await probe.fetchToken(uri));
            token = fetched.token;
          } catch (error) {
            statusCache?.setNegative(uri, error, nowSeconds);
            fetchError = error;
          }
        }
        if (token === undefined) {
          const outcome = await decideFetchFailure(
            opts,
            failOpenWindow,
            uri,
            nowSeconds,
            lookup.stale,
          );
          if (outcome === undefined) {
            throw fetchError;
          }
          warning = outcome.warning;
          if (outcome.token === undefined) {
            // FO-1: 失効状態を確認できなかったことを警告に含めて有効と返す。
            return {
              valid: true,
              purpose,
              value: STATUS_VALUE_VALID,
              warnings: [warning],
            };
          }
          // FO-2: stale な実データを通常どおり検証し、実際の失効状態を返す。
          token = outcome.token;
        }
      }

      // 2-3. 署名と sub 一致を検証する（取得経路に依らず必ず通す）。
      const verified = verifyStatusListToken(token, uri, issuerPublicKey);

      // `exp` の型検証は `verifyStatusListToken` が済ませている（不正な `exp` は 3002 で拒否済み）。
      // ここに来る `undefined` は「`exp` 不在」だけを意味する。
      const expSeconds = ownProperty<number>(verified, 'expSeconds');

      // 新規取得した Token は `exp` に達していれば拒否する。FO-2 で stale な Token を再利用する場合は
      // 署名と sub を確かめた上でそのビット値を読み取る。通常のキャッシュ利用では `cacheFetchedToken`
      // が格納時に TTL を `exp` で切り詰めているので、期限切れが返ることはない。
      if (
        fetched !== undefined &&
        expSeconds !== undefined &&
        (!Number.isFinite(nowSeconds) || nowSeconds >= expSeconds)
      ) {
        throw new VericertsError(ErrorCodes.VC_EXPIRED);
      }

      // 取得に成功した計時の破棄は、署名・sub・exp・鮮度の検証を通った新規取得分だけが行う。
      // 検証前に破棄すると、キャプティブポータルの 200 HTML など検証不能な応答 1 回で
      // 60 秒の fail-open 上限が巻き戻り、失効済み VC が無期限に通る。stale 再利用（`fetched`
      // 無し）は取得に成功していないので触らない。
      // 古い Token の再生（`exp` 無しの失効前 Token など）は `iat` / `ttl` / 既観測 `iat` で弾く
      // `exp` 判定と同じ理由で新規取得分に限る。
      if (fetched !== undefined) {
        freshness.admitFetched(uri, verified, nowSeconds);
        failOpenWindow.clear(uri);
      }

      // 真正性を確認できた新規取得分だけをキャッシュへ格納する（stale 再利用時は再格納しない）。
      const fetchedCacheControl =
        fetched === undefined ? undefined : ownProperty<string>(fetched, 'cacheControl');
      if (fetched !== undefined && statusCache !== undefined) {
        cacheFetchedToken({
          cache: statusCache,
          uri,
          token,
          maxTtlSeconds,
          nowSeconds,
          // `fetched` は `normalizeTokenResponse` が**呼び出し側の戻り値をそのまま返した**もので
          // あり（文字列以外は素通し）、SDK が構築したオブジェクトではない。`cacheControl` を
          // プロトタイプ鎖で読んでここへ詰め直すと own プロパティに化け、`cacheFetchedToken`
          // 側の own 限定読み取りが無効化される（`Cache-Control` を返していない Issuer 応答でも
          // 汚染値の `max-age` が実効 TTL に効く）。
          ...(fetchedCacheControl === undefined ? {} : { cacheControl: fetchedCacheControl }),
          expSeconds: freshness.effectiveExpSeconds(verified),
        });
      }

      // 4-5. lst を展開し idx のビット値を読み取る。
      const value = await readStatusBit(verified, idx);

      // 6. 値が 0 なら有効。FO-2 で stale なデータを使った場合はその旨を警告で添える。
      return {
        valid: value === 0,
        purpose,
        value,
        ...(warning === undefined ? {} : { warnings: [warning] }),
      };
    },
  };

  // 判定回数は取得経路に依らず `resolve` 1 回につき 1 件なので、検証フローの内側ではなく
  // 外側で数える（早期 return と送出の両方を 1 箇所で拾う）。
  return countStatusListChecks(resolver, metrics);
}
