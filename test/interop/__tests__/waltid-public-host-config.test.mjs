// test/interop/__tests__/waltid-public-host-config.test.mjs
//
// 同梱の walt.id 構成が SDK の公開ホスト検査（`isPublicHttpsUrl`）を通る名前で公開されていることの
// 回帰テスト。`baseUrl` が `https://localhost:…` だと offer / `response_uri` が
// Offer 取得後・Receive 前に 3004 で拒否され、`interop:waltid-issuer:vericerts` /
// `interop:vericerts:waltid-verifier` が常時 skipped になる。SDK の検査自体は緩めない。
//
// 実行: `bun test test/interop/__tests__/waltid-public-host-config.test.mjs`（要 Bun、要 `cd sdk && bun install`）。

import { describe, expect, it } from 'bun:test';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isPublicHttpsUrl } from '@vericerts/vericerts-wallet-sdk/common';

const read = (relative) => readFileSync(new URL(`../${relative}`, import.meta.url), 'utf8');

/** `*.conf`（HOCON）から、コメントでない `baseUrl = "…"` を取り出す。 */
function baseUrlOf(relative) {
  const match = /^baseUrl\s*=\s*"([^"]+)"/m.exec(read(relative));
  if (match === null) throw new Error(`${relative} に baseUrl が無い`);
  return match[1];
}

const SERVICES = [
  { name: 'issuer', conf: 'waltid/issuer-config/issuer-service.conf', port: 8097 },
  { name: 'verifier', conf: 'waltid/verifier-config/verifier-service.conf', port: 8098 },
];

describe('同梱の walt.id baseUrl は SDK の公開ホスト検査を通る', () => {
  for (const { name, conf, port } of SERVICES) {
    it(`${name}: baseUrl は公開ホスト宛の HTTPS で、TLS プロキシのポートを指す`, () => {
      const baseUrl = baseUrlOf(conf);
      expect(isPublicHttpsUrl(baseUrl)).toBe(true);
      expect(new URL(baseUrl).port).toBe(String(port));
    });
  }
});

describe('baseUrl の FQDN を compose の DNS・nginx・証明書が揃って解決・終端する', () => {
  const hosts = SERVICES.map(({ conf }) => new URL(baseUrlOf(conf)).hostname);

  it('compose の waltid-tls-proxy が全 FQDN を network alias として持つ', () => {
    const compose = read('docker-compose.yml')
      .split('\n')
      .filter((line) => !line.trim().startsWith('#'))
      .join('\n');
    const proxy = /^ {2}waltid-tls-proxy:\n((?: {4,}.*\n|\n)+)/m.exec(compose)?.[1] ?? '';
    for (const host of hosts) {
      expect(proxy).toMatch(new RegExp(`^\\s+- ${host.replaceAll('.', '\\.')}\\s*$`, 'm'));
    }
  });

  it('nginx の server_name が各ポートの FQDN に一致する', () => {
    const nginx = read('nginx/waltid-tls-proxy.conf');
    for (const { conf, port } of SERVICES) {
      const host = new URL(baseUrlOf(conf)).hostname;
      expect(nginx).toMatch(
        new RegExp(`listen ${port} ssl;\\s+server_name ${host.replaceAll('.', '\\.')};`),
      );
    }
  });

  it('サーバ証明書が全 FQDN を SAN に持ち、同梱の CA で署名され、有効期間内', () => {
    const ca = new X509Certificate(read('waltid/tls/ca-cert.pem'));
    const server = new X509Certificate(read('waltid/tls/server-cert.pem'));
    for (const host of hosts) {
      expect(server.checkHost(host)).toBe(host);
    }
    expect(server.verify(ca.publicKey)).toBe(true);
    const now = Date.now();
    expect(Date.parse(server.validFrom)).toBeLessThanOrEqual(now);
    expect(Date.parse(server.validTo)).toBeGreaterThan(now);
  });
});
