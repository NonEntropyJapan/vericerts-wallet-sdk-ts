/**
 * 「大入力の上限・走査量予算を pin する」テストの共有タイムアウト。規則の実体を 1 箇所に置く。
 *
 * 上限の強制を示すには上限ちょうど（と 1 超）の入力を実際に通す必要があり、数百 ms〜数秒の CPU を使う
 * （例: 512 版の webvh ログの追記と検証、60 万件の type、200 万要素の XML、TypeScript の型解決を通る検出器）。
 * 単独実行の実測は最大でも約 3 s だが、pre-push（lefthook `parallel: true` で sdk と extension のテストが
 * 同時実行される）や load average 30〜58 の環境では 5〜12 倍に伸び、bun の既定 5000 ms を超えて
 * 変更に無関係に落ちていた。
 *
 * 入力の大きさは「上限を強制していること」の主張そのものなので縮めない。ハング検知は保ちつつ、負荷では落ちない
 * 水準として 120 s を与える（単独 3.1 s の検出器ゲートが、busy loop 128 本の負荷で 153 s かかった実測がある）。
 * KDF を通るテストの `KDF_TIMEOUT_MS`（`keymanager/__tests__/kdf-policy/kdf-timeout.ts`）と同じ値だが、
 * 意味が違う（こちらは CPU 量、あちらは KDF のメモリ帯域）ので別の定数にしている。
 *
 * 使い方: 該当ファイルの先頭で `setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS)` を呼ぶ。`setDefaultTimeout` は
 * ファイル単位で効く（他ファイルの閾値は緩まない。bun 1.4.2 で確認済み）。
 */
export const HEAVY_INPUT_TIMEOUT_MS = 120_000;
