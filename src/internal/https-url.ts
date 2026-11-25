/**
 * HTTPS の絶対 URL かどうかの判定（横断ヘルパー）。
 *
 * **配置**: `src/internal` 直下の横断ヘルパー。
 * 元は `auth/oid4vci/oid4vci-url-guards.ts`（Protocol）にあったが、`eudi`（Domain）の WUA 取得・
 * Issuer Metadata / Nonce Endpoint 取得が同じ入口検査を必要とし、そのまま参照すると
 * Domain → Protocol の逆方向依存になる。プロトコル固有の要素を持たない純粋な URL 検査
 * なので、`fetch-di.ts` と同じ理由で横断へ移した。
 *
 * **なぜ 1 か所に集約するか。** 平文 HTTP のエンドポイントを素通りさせると、`client_assertion`
 * （`<WUA>~<WUA-PoP>`）・Bearer access_token・VP Token・WUA JWT を TLS 保護なしで送出しうる。
 * 判定が経路ごとに複製されていると、片方だけ条件がずれて「一方の経路だけ非 HTTPS を通す」状態が
 * 生まれ、しかもテストは各経路が個別に緑のままになる。
 *
 * 空文字・空白のみの拒否は `non-empty-string.ts` の `isNonBlankString` が担う（コードベース全体で
 * 1 つの規則にするため）。本モジュールは依存を持たない。
 */

/**
 * URL として解釈でき、かつスキームが `https:` かを検証する。
 *
 * @param value 検証対象の URL 文字列。
 * @returns HTTPS の絶対 URL として解釈できれば `true`。
 */
export function isHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * 突き合わせに使える URL の origin（`scheme://host[:port]`）を取り出す。
 *
 * OID4VP `response_uri` ↔ `client_id`、JAR の SAN ↔ `client_id`、SIOPv2 の
 * `redirect_uri` ↔ `client_id` は導出を 1 か所（`URL.origin`）に揃える。次は `undefined`（取れない）:
 * - URL として解釈できない（スキームなし・`x509_san_dns:` 等の prefixed 識別子）。
 * - 不透明 origin `'null'`（`did:web:...`）。別々の識別子どうしが `'null'` で一致扱いになるため。
 * - userinfo を含む。`https://bank.example@evil.example` の origin は `https://evil.example` だが、
 *   `client_id` は同意 UI や ID Token の `aud` にそのまま使われ表示 RP を詐称できる。
 */
export function comparableOrigin(value: string): string | undefined {
  try {
    const url = new URL(value);
    const opaque = url.origin === 'null' || url.username !== '' || url.password !== '';
    return opaque ? undefined : url.origin;
  } catch {
    return undefined;
  }
}
