/**
 * `WalletOptions.didNodeUrls` で指定する、DID 自体から解決先が決まらないメソッドの接続先。
 *
 * did:ebsi / did:ion / did:cheqd は、呼び出し側が選んだノード / リゾルバーの URL（`https:` のみ）で解決し、
 * DID 文字列からは導出しない。**指定したメソッドだけを登録する**（未指定なら `resolveDID` は `2002`）。
 * 信頼の根は指定したノード / リゾルバーの運営者になる。cheqd は既定のリゾルバーがあるが、運営者を
 * 信頼の前提に持ち込むため、明示しない限り登録しない。
 */
export interface DidNodeUrls {
  /** did:ebsi の解決に用いる EBSI ノードの API ベース URL（`https://api-<env>.ebsi.<運営者のドメイン>`）。 */
  readonly ebsi?: string;
  /** did:ion の解決に用いる Sidetree ノードのベース URL（`<nodeUrl>/identifiers/<did>`）。 */
  readonly ion?: string;
  /** did:cheqd の解決に用いるリゾルバーのベース URL。`https://resolver.cheqd.net` を使う場合も明示する。 */
  readonly cheqd?: string;
}
