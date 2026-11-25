/**
 * 「公開インターネット上の HTTPS URL」かどうかの判定（横断ヘルパー）。
 *
 * DID Document の `serviceEndpoint` のように**相手が制御する URL** へ POST する経路は、
 * `isHttpsUrl`（スキーム検査のみ）だけでは `https://localhost/` や `https://169.254.169.254/`
 * （クラウドメタデータ）、`https://10.0.0.1/` といったローカルネットワーク宛の送信（SSRF）を
 * 防げない。そこでホストがループバック / プライベート / リンクローカル等の IP リテラル、
 * または公開 DNS 名として解決され得ないホスト名（`localhost` 系・ドット無しの単一ラベル・
 * `.local` / `.internal` / `.lan` / `.home.arpa` / `.corp` 等の予約 TLD）の場合も拒否する。
 * IPv6 は許可リスト方式（グローバルユニキャスト `2000::/3` と、IPv4 埋め込み形式のうち埋め込み先が
 * 公開のものだけを許す）。
 *
 * **限界**: 判定は URL 文字列だけで行う。公開 DNS 名がプライベート IP へ解決される場合
 * （DNS rebinding 等）はここでは検知できない（fetch 実装側のネットワーク制御に委ねる）。
 */

import { isHttpsUrl } from '../https-url.js';

/** IPv4 の内部用途・非ユニキャスト範囲（先頭オクテット / 第 2 オクテットで判定する）。 */
function isNonPublicIpv4(octets: readonly number[]): boolean {
  const [a, b, c] = octets as [number, number, number];
  return (
    a === 0 || // 0.0.0.0/8
    a === 10 || // 10.0.0.0/8
    a === 127 || // loopback
    (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10 (CGNAT)
    (a === 169 && b === 254) || // link-local / cloud metadata
    (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
    (a === 192 && b === 0 && c === 0) || // 192.0.0.0/24
    (a === 192 && b === 168) || // 192.168.0.0/16
    (a === 198 && (b === 18 || b === 19)) || // 198.18.0.0/15 (benchmark)
    a >= 224 // multicast / reserved / broadcast
  );
}

/** 8 グループへ展開した IPv6 を返す（`URL` が正規化済みの `::` 圧縮形・IPv4 末尾形を想定）。 */
function expandIpv6(address: string): number[] | undefined {
  let text = address;
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const parts = tail.split('.').map(Number);
    if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
      return undefined;
    }
    const [a, b, c, d] = parts as [number, number, number, number];
    text = `${text.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) {
    return undefined;
  }
  const head = halves[0] === '' ? [] : (halves[0] as string).split(':');
  const rest = halves[1];
  const tailGroups = rest === undefined || rest === '' ? [] : rest.split(':');
  const missing = 8 - head.length - tailGroups.length;
  if ((rest === undefined && missing !== 0) || (rest !== undefined && missing < 1)) {
    return undefined;
  }
  const groups = [
    ...head,
    ...Array<string>(rest === undefined ? 0 : missing).fill('0'),
    ...tailGroups,
  ];
  const values = groups.map((g) =>
    /^[0-9a-f]{1,4}$/i.test(g) ? Number.parseInt(g, 16) : Number.NaN,
  );
  return values.length === 8 && values.every((v) => !Number.isNaN(v)) ? values : undefined;
}

function isNonPublicIpv6(address: string): boolean {
  const groups = expandIpv6(address);
  if (groups === undefined) {
    return true; // 解釈できない IPv6 リテラルは fail-closed。
  }
  const [g0, g1, g2, g3, g4, g5, g6, g7] = groups as [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  const embedded = [g6 >> 8, g6 & 0xff, g7 >> 8, g7 & 0xff];
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0) {
    // IPv4 を下位 32bit に埋め込む形式は、埋め込み IPv4 で判定する。
    //   ::ffff:a.b.c.d       IPv4-mapped（g4 = 0, g5 = 0xffff）
    //   ::ffff:0:a.b.c.d     IPv4-translated / SIIT, RFC 2765（g4 = 0xffff, g5 = 0）
    //   ::a.b.c.d            IPv4-compatible（g4 = g5 = 0。:: と ::1 は常に非公開）
    if ((g4 === 0 && g5 === 0xffff) || (g4 === 0xffff && g5 === 0)) {
      return isNonPublicIpv4(embedded);
    }
    if (g4 === 0 && g5 === 0) {
      return (g6 === 0 && g7 <= 1) || isNonPublicIpv4(embedded);
    }
  }
  if (g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
    // 64:ff9b::/96（NAT64）は埋め込まれた IPv4 で判定する。
    return isNonPublicIpv4(embedded);
  }
  // 上記以外は許可リスト方式: グローバルユニキャスト `2000::/3` だけを公開とみなす。
  // fc00::/7 ULA / fe80::/10 link-local / fec0::/10 site-local / ff00::/8 multicast /
  // 100::/64 discard / 64:ff9b:1::/48（局所用 NAT64）/ ::/8 のその他は、すべてここで拒否される。
  if ((g0 & 0xe000) !== 0x2000) {
    return true;
  }
  return (
    g0 === 0x2002 || // 6to4（IPv4 を埋め込むため一律拒否）
    (g0 === 0x2001 && g1 < 0x200) || // 2001::/23 IETF 予約（Teredo 2001::/32・ORCHID・benchmark 等）
    (g0 === 0x2001 && g1 === 0xdb8) || // 2001:db8::/32 ドキュメント用
    (g0 === 0x3fff && g1 < 0x1000) // 3fff::/20 ドキュメント用（RFC 9637）
  );
}

/**
 * 公開 DNS 名として解決され得ない、家庭 / 企業 LAN・mDNS・ローカル用の予約 TLD。
 * 検索ドメイン補完（`*.corp.example.com`）や社内 DNS で内部ホストへ解決される名前を拒否する。
 */
const NON_PUBLIC_TLDS: ReadonlySet<string> = new Set([
  'localhost',
  'local',
  'localdomain',
  'internal',
  'lan',
  'home',
  'corp',
  'intranet',
  'private',
  'arpa', // home.arpa（RFC 8375）・in-addr.arpa / ip6.arpa（逆引き）
]);

/** ホスト名（IP リテラル以外）が公開 DNS 名として妥当かを判定する。 */
function isPublicDnsName(host: string): boolean {
  const labels = host.split('.');
  // ドット無しの単一ラベル（`intranet` / `router`）は OS の検索ドメインや LLMNR / mDNS で内部ホストへ
  // 解決され得るため拒否する。
  if (labels.length < 2 || labels.some((label) => label === '')) {
    return false;
  }
  const tld = labels[labels.length - 1] as string;
  // TLD は英字のみ（または IDN の punycode `xn--`）。数字入りの TLD は IP 表記ゆれの取りこぼしでもある。
  return /^(?:[a-z]{2,}|xn--[a-z0-9-]+)$/.test(tld) && !NON_PUBLIC_TLDS.has(tld);
}

/**
 * HTTPS で、かつホストがローカル / プライベート / リンクローカル宛でない URL かを検証する。
 *
 * @param value 検証対象の URL 文字列。
 * @returns 公開ホスト宛の HTTPS URL として解釈できれば `true`。
 */
export function isPublicHttpsUrl(value: string): boolean {
  if (!isHttpsUrl(value)) {
    return false;
  }
  // `URL` はホストを小文字化し、`0x7f.1` / `2130706433` 等の IPv4 表記ゆれも dotted decimal へ正規化する。
  const host = new URL(value).hostname.replace(/\.$/, '');
  if (host === '') {
    return false;
  }
  if (host.startsWith('[') && host.endsWith(']')) {
    return !isNonPublicIpv6(host.slice(1, -1));
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    return !isNonPublicIpv4(host.split('.').map(Number));
  }
  return isPublicDnsName(host);
}

/**
 * `redirect: 'manual'` で送った POST の応答が「リダイレクトされた / 追従された」かの判定。
 *
 * 秘密を含む本文（pre-authorized_code・code_verifier・client_assertion・access_token 等）を持つ POST は、
 * 307 / 308 に追従されると本文ごと別ホスト（内部ネットワーク含む）へ再送される。POST 送信側は
 * `redirect: 'manual'` を指定し、下の判定が真の応答を失敗として扱う。`manual` の返り方は実装差があり
 * （ブラウザは `opaqueredirect` / `status=0`、Node・Bun は 3xx をそのまま返す）、注入された fetch が
 * 指定を無視して追従した場合に備え最終 URL（`response.url`）の公開 HTTPS 検査も併せる。
 * 構築済み `Response`（テスト等）では `url` が空文字列になるため URL 検査は行わない。
 */

/** 応答がリダイレクト（opaqueredirect / 3xx）なら `true`。 */
export function isRedirectResponse(response: Response): boolean {
  return response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400);
}

/**
 * 応答がリダイレクト（opaqueredirect / 3xx）、または非公開 / 非 HTTPS の最終 URL なら `true`。
 */
export function isRedirectedResponse(response: Response): boolean {
  return (
    isRedirectResponse(response) || (response.url.length > 0 && !isPublicHttpsUrl(response.url))
  );
}

/**
 * ループバック（開発ノード）宛も許す POST 用の「リダイレクトされたか」判定。
 *
 * 宛先が公開 HTTPS なら {@link isRedirectedResponse} と同じ（3xx と非公開な最終 URL を拒否）。
 * 初回 URL が公開 HTTPS 以外（`http://127.0.0.1:5001` 等、呼び出し側が許したループバック）のときは、
 * 最終 URL が自分自身でも非公開になるため URL 検査はせず、3xx / opaqueredirect だけを拒否する
 * （どちらの場合もリダイレクトは追従しない）。
 *
 * @param requestUrl POST を送った URL。
 * @param response `redirect: 'manual'` で受けた応答。
 */
export function isRedirectedPostResponse(requestUrl: string, response: Response): boolean {
  return isPublicHttpsUrl(requestUrl)
    ? isRedirectedResponse(response)
    : isRedirectResponse(response);
}
