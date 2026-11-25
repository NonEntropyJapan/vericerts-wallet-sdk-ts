/**
 * `linked_dids` の最大件数。1 回の検証で解決できる異なる DID の上限と同じく 32 件。
 * 各 DLC の検証は発行者 DID 解決（外部 I/O）を伴うため、外部オリジンが任意件数を指定して
 * Verifier ホストから大量の外向き要求を出させないよう、超過は 1 件も解決せず
 * `invalid_did_configuration` に倒す。
 *
 * 拡張の `verifyDIDConfiguration` も同じ上限を使う。
 * facade は ethers 等の重い依存を引くため、定数だけを依存ゼロのこのモジュールへ置いて共有する。
 */
export const MAX_LINKED_DIDS = 32;
