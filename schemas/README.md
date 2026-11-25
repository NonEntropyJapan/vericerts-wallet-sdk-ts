# SDK のスキーマとテストベクタ

`error-codes.json` はエラーコードの公開レジストリ、`log-entry.json` は構造化ログの JSON Schema です。この 2 ファイルを直接編集できます。SDK のルートで次のコマンドを実行すると、JSON を整形し、エラー定数・実装・関連 API の回帰テストを実行します。ログについては、スキーマ全体が Draft 2020-12 としてコンパイルできること、Logger の出力やトレース ID・スパン ID が公開仕様に合うことを検査します。スキーマのコンパイラは開発時にのみ使用します。

```sh
bun install --frozen-lockfile
bun run gen:error-codes && bun run check:error-codes
bun run gen:log-entry-schema && bun run check:log-entry-schema
```

`conformance-vectors.json` は他言語の実装と共有する入力・期待値です。ケースは `scripts/conformance/` で編集し、SDK の実装で再生成します。`generatedFrom` には SDK のパッケージ名とバージョンを記録します。

```sh
bun run gen:conformance-vectors && bun run check:conformance-vectors
```
