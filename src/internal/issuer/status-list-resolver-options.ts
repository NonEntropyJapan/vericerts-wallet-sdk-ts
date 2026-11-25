/**
 * Token Status List 解決時の取得・キャッシュ・検証・監査に使うオプション。
 */

import type { TtlCache } from '../cache/index.js';
import type {
  FailSafeAuditContext,
  FailSafeAuditRecord,
  FailSafeDecision,
  FailSafePolicy,
} from '../failsafe-policy/index.js';
import type { PublicKeyJwk } from '../identity/did.js';
import type { Metrics } from '../observability/metrics.js';
import type { StatusListCacheEvent, StatusListTokenResponse } from './status-list-cache.js';
import type { StatusPurpose } from './status-list-types.js';

/** `createStatusListResolver` のオプション。 */
export interface StatusListResolverOptions {
  /**
   * Status List Token を URI から取得する関数（DI）。
   *
   * ネットワーク I/O は SDK コアに持ち込まず呼び出し側へ委譲する（テスト容易性・依存最小化）。
   * 取得失敗時は呼び出し側で投げてよい（FO-1 / FO-2 の成立条件を満たさなければ本解決器はそのまま伝播する）。
   *
   * 素の Token 文字列を返してもよい（後方互換）。その場合 `Cache-Control` が得られないため、
   * キャッシュ TTL は設定された上限（既定 60 秒）をそのまま採用する。`Cache-Control` を尊重
   * させたい場合は `StatusListTokenResponse` を返す。
   */
  readonly fetchToken: (uri: string) => Promise<string | StatusListTokenResponse>;
  /** Status List Token の署名検証に使う Issuer の EC 公開鍵 JWK。 */
  readonly issuerPublicKey: PublicKeyJwk;
  /**
   * この解決器が評価する用途（`revocation` / `suspension`）。
   *
   * Token Status List は用途ごとに別リストで運用する。`StatusReference` 自体は用途を
   * 持たないため、解決器の構築時に用途を指定し `StatusCheckResult.purpose` に反映する。
   */
  readonly purpose: StatusPurpose;
  /**
   * Status List Token のキャッシュ（任意）。
   *
   * 未指定なら従来どおり毎回 `fetchToken` する。`createStatusListCache` で生成する。
   * キーは `status.status_list.uri`、値は生の Token（JWT 文字列）。
   */
  readonly statusCache?: TtlCache<string>;
  /**
   * キャッシュ TTL の上限（秒、任意）。既定かつハードキャップは 60 秒。
   *
   * 短縮（例: 30）は安全側の変更のため許可し、緩和（61 以上）は拒否する。
   */
  readonly maxTtlSeconds?: number;
  /**
   * `ttl` クレームを持たない Status List Token に課す年齢上限（秒、任意）。既定 24 時間。
   *
   * 新規取得した Token の `now - iat` がこの値（Token が `ttl` を持つならそれ）以上なら
   * `VC_EXPIRED`（3024）で拒否する。署名付きでも古い Token の再生（失効前の Token を配信経路が返し
   * 続ける）は署名では防げないため。正の整数のみ受理する。Token を滅多に再発行しない
   * Issuer を使う場合は、その運用に合わせて引き上げる（引き上げは失効反映の遅れを許す選択になる）。
   */
  readonly maxTokenAgeSeconds?: number;
  /** キャッシュ状態（`cold` / `warm` / `hot`）の観測フック（任意）。 */
  readonly onCacheEvent?: (event: StatusListCacheEvent) => void;
  /**
   * メトリクス出力先（任意）。未指定なら何も記録しない。
   *
   * `vericerts_status_list_fetch_duration_seconds`（取得レイテンシ、label `cache`）と
   * `vericerts_status_list_check_total`（判定回数、label `result`）の 2 系列を積む。
   * `onCacheEvent` が呼び出し側へ観測値を**渡すフック**なのに対し、こちらは SDK 自身が系列へ
   * **積むための出力先**であり、両立する（計装を有効にしてもフックはそのまま呼ばれる）。
   * ラベルの種類と件数を制限する計器（`createMetrics`）を渡すこと。
   */
  readonly metrics?: Metrics;
  /**
   * Fail-safe ポリシーの override（任意）。
   *
   * 取得失敗が猶予期間内で、同意と監査記録の条件を満たす場合は警告付きで続行できる。FO-1 / FO-2 を
   * `escalate` に挙げると取得失敗を Fail-closed に固定できる。`suppressPrompt` に挙げると同意プロンプトを
   * 省いて通過する（同意事実の記録責務は SDK 利用者に移る）。
   */
  readonly failSafePolicy?: FailSafePolicy;
  /**
   * Fail-open 判定の監査ログ記録先。同意（`accepted`）・不同意
   * （`rejected`）のいずれでも呼ばれる。監査記録先がない場合は拒否する。
   */
  readonly onPolicyEvent?: (record: FailSafeAuditRecord) => void;
  /**
   * UI 警告を出しユーザー同意を取るコールバック（任意）。
   *
   * `suppressPrompt` で同意プロンプトを省略する場合を除き、未指定時は取得失敗として扱う。
   */
  readonly requestConsent?: (decision: FailSafeDecision) => boolean | Promise<boolean>;
  /** 監査レコードへ付与する相関情報（任意）。 */
  readonly auditContext?: FailSafeAuditContext;
  /** Fail-open を継続できる最大秒数（既定 `DEFAULT_FAIL_OPEN_MAX_SECONDS` = 60 秒）。 */
  readonly failOpenMaxSeconds?: number;
  /** 現在時刻（エポック秒）を返す関数。テストの決定性のため注入する。既定はシステム時刻。 */
  readonly nowSeconds?: () => number;
}
