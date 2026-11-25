/**
 * 証明書の名前が nameConstraints を満たすかの照合（RFC 5280 §4.2.1.10 / §6.1.4 (g)）。
 *
 * **なぜ読み取りと分けるか。** `name-constraints.ts` は拡張を構造体へ読むところまでを担い、本
 * モジュールはその構造体と証明書の名前（subject DN / SAN）を突き合わせる。CA 制約で言えば
 * `ca-constraints.ts`（読む）と `etsi-tsl/chain.ts`（課す）の関係と同じで、「何と書いてあるか」と
 * 「それを満たすか」を混ぜないほうが、どちらの判断も単独で読める（1 ファイル 300 行の上限にも収まる）。
 *
 * 照合できる名前形式は directoryName と URI だけである。理由は `name-constraints.ts` 冒頭に書いた
 * とおりで、評価規約を持たない名前形式・読めない表現は「制約なし」ではなく**拒否**に倒す。
 *
 * セキュリティ上の注意:
 * - 例外を投げず真偽値で返す。戻り値・例外に証明書本文 / DN / 鍵素材を含めない。
 */

import { normalizedRdns } from './dn.js';
import type { AltNames, NameConstraints } from './name-constraints.js';

/**
 * 証明書の名前（subject DN / SAN）が制約を満たすか。
 *
 * @param subjectDer subject DN の DER バイト列。
 * @param altNames `name-constraints.ts` の `altNamesOf` の結果。
 * @param constraints 上位 CA が課す制約。
 * @returns 満たすなら `true`。評価できない名前・制約を含む場合は `false`（fail-closed）。
 */
export function namesSatisfyConstraints(
  subjectDer: Uint8Array,
  altNames: AltNames,
  constraints: NameConstraints,
): boolean {
  if (!constraints.evaluable || altNames.hasUnevaluable) {
    return false;
  }
  const rdns = normalizedRdns(subjectDer);
  if (rdns === undefined) {
    return false;
  }
  const hosts = hostsToMatch(altNames.uris, constraints);
  if (hosts === undefined) {
    return false;
  }
  // 空の subject（RDN 0 個）は directoryName の検査対象外。RFC 5280 §4.2.1.10 は
  // directoryName の制約を「証明書が持つ名前」に対して課すと定めており、名前を持たない
  // subject には課しようがない（識別子は SAN 側で主張される）。
  const directoryNames = rdns.length === 0 ? [] : [rdns];
  return (
    withinPermitted(directoryNames, constraints.permitted.directoryNames, dnWithinBase) &&
    withinPermitted(hosts, constraints.permitted.uris, hostWithinBase) &&
    notExcluded(directoryNames, constraints.excluded.directoryNames, dnWithinBase) &&
    notExcluded(hosts, constraints.excluded.uris, hostWithinBase)
  );
}

/**
 * URI SAN を照合用のホストへ畳む。
 *
 * **URI base が 1 つも無ければ照合しない。** その場合 URI は制約の対象外なので、ホストを
 * 取り出せない SAN（`urn:uuid:…` / `mailto:…` のような非階層 URI）があっても証明書を落とす
 * 理由が無い。以前は制約が directoryName base しか持たない場合でも、そうした SAN を 1 件
 * 載せるだけで証明書全体が拒否されていた。
 *
 * 逆に URI base があるなら、ホストを取り出せない URI は「制約を満たすか判定できない」ので
 * `undefined`（= 呼び出し側で拒否）に倒す（fail-closed）。
 */
function hostsToMatch(
  uris: readonly string[],
  constraints: NameConstraints,
): readonly string[] | undefined {
  if (constraints.permitted.uris.length === 0 && constraints.excluded.uris.length === 0) {
    return [];
  }
  const hosts: string[] = [];
  for (const uri of uris) {
    const host = hostOf(uri);
    if (host === undefined) {
      return undefined;
    }
    hosts.push(host);
  }
  return hosts;
}

/**
 * その種別の base が 1 つ以上あるとき、証明書側の名前すべてがいずれかの base に含まれるか。
 *
 * base が無い種別は無制約（`true`）。証明書側にその種別の名前が無ければ空の全称で `true`。
 */
function withinPermitted<TName, TBase>(
  names: readonly TName[],
  bases: readonly TBase[],
  contains: (base: TBase, name: TName) => boolean,
): boolean {
  if (bases.length === 0) {
    return true;
  }
  return names.every((name) => bases.some((base) => contains(base, name)));
}

/** 証明書側の名前がいずれの base にも含まれないか。 */
function notExcluded<TName, TBase>(
  names: readonly TName[],
  bases: readonly TBase[],
  contains: (base: TBase, name: TName) => boolean,
): boolean {
  return !names.some((name) => bases.some((base) => contains(base, name)));
}

/** base の RDN 列が候補の RDN 列の先頭一致か（RFC 5280 §4.2.1.10 の directoryName 包含）。 */
function dnWithinBase(base: readonly string[], name: readonly string[]): boolean {
  return base.length <= name.length && base.every((rdn, i) => rdn === name[i]);
}

/**
 * ホストが URI base に含まれるか。
 *
 * base が `.` で始まるならサブドメインのみに一致する（`.example.com` は `host.example.com` に
 * 一致するが `example.com` 自身には一致しない）。そうでなければ完全一致。
 */
function hostWithinBase(base: string, host: string): boolean {
  return base.startsWith('.') ? host.endsWith(base) : host === base;
}

/**
 * SAN URI からホストを取り出す（標準の `URL` を使い、自前パースはしない）。
 *
 * ホストを持たない非階層 URI（`urn:uuid:…` 等）は `undefined` になる。これは「制約に照らして
 * 判定できない」の意味であり、呼び出し側（{@link hostsToMatch}）が URI base の有無で
 * 拒否するかどうかを決める。
 *
 * **末尾の root label ドットは落とす。** WHATWG URL は `https://blocked.example.com./vc` の
 * hostname を `blocked.example.com.` のまま返すが、DNS 上これは `blocked.example.com` と同じ
 * ホストである。落とさないと `'blocked.example.com.'.endsWith('.example.com')` が false になり、
 * `excludedSubtrees` の base `.example.com` で除外したはずの名前が**素通り**する（一方
 * `permittedSubtrees` は同じ条件で fail-closed 側へ倒れるので、これは除外専用のバイパスになる）。
 *
 * **空ラベルを含むホストは判定不能に倒す。** `a..b` / `.` のようにラベルが空になる表現は
 * WHATWG URL が受理するが、`hostWithinBase` の接尾辞一致に載せると境界の意味が定まらない。
 * 「一致しない」ではなく `undefined`（= 呼び出し側で拒否）に倒す（fail-closed）。
 */
function hostOf(uri: string): string | undefined {
  let host: string;
  try {
    host = new URL(uri).hostname.toLowerCase();
  } catch {
    return undefined;
  }
  const withoutRootLabel = host.endsWith('.') ? host.slice(0, -1) : host;
  if (withoutRootLabel.length === 0 || withoutRootLabel.split('.').includes('')) {
    return undefined;
  }
  return withoutRootLabel;
}
