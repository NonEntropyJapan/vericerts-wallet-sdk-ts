# didwebvh-test-suite（ベンダリングした公式テストベクタ）

このディレクトリは、DIF の did:webvh v1.0 相互運用テスト [`decentralized-identity/didwebvh-test-suite`](https://github.com/decentralized-identity/didwebvh-test-suite)
のテストベクタ（`vectors/`）の一部を、変更せずに複製したものです。SDK の did:webvh 実装が、公式のベクタと同じ結果を返す
ことを `../vectors.test.ts` で確かめるために使います。

| 項目 | 内容 |
| --- | --- |
| 出典 | <https://github.com/decentralized-identity/didwebvh-test-suite> |
| 固定したコミット | `703f97fae37cc394ce10340d8d0815dab63573f6`（main、2026-09-22 の[上流のマージ](https://github.com/decentralized-identity/didwebvh-test-suite/pull/21)） |
| ライセンス | Apache License 2.0（`LICENSE`。出典リポジトリの `LICENSE` と同一） |
| 複製した範囲 | `vectors/` の全シナリオ（`script.yaml`、負のベクタの `README.md`、`NEGATIVE_VECTORS.md`）と、実装別の出力のうち `ts` / `python` / `rust` / `java`（`did.jsonl`・`did-witness.json`・`resolutionResult.json`）。`dart` と `java-eecc` は他の実装と同じ内容のため含めない |
| 変更 | なし（バイト単位で同一。テストは読み取るだけ） |

更新するときは、出典のコミットを選び直して `vectors/` を丸ごと差し替え、上の表のコミットを書き換えます。

## テストでの扱い（`../vectors.test.ts`）

- 負のベクタ（`negative-*`）は、ログ・DID が解決時に拒否されること（`invalidDid` 相当 = 2001）を確かめる。
- 正のベクタは、`resolutionResult.json` の DID Document と解決メタデータ（`versionId` / `created` / `updated` / `scid` /
  `portable` / `deactivated` / `watchers`）に一致することを確かめる。ログは**署名し直さず、そのまま**解決させる。
- ベクタのログは `proof.challenge` を持たない（仕様に `challenge` の要件がないため）。SDK は `challenge` を要求しない
  （`proof.challenge === versionId` の検査は行わない。ログ位置は `versionId` を含む署名対象と entryHash の連鎖が束縛する）。
- ベクタの proof の署名入力が仕様（`SHA256(JCS(proofConfig)) ‖ SHA256(JCS(entry))`）と byte 単位で一致すること、
  `proofValue` の 1 ビット・proof の各メンバ・署名対象の本文の改変が拒否されることも確かめる。
