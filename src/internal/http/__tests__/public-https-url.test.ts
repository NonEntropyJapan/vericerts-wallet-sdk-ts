/**
 * isPublicHttpsUrl の公開ホスト判定。
 *
 * 単一ラベル・内部用 TLD・IPv6 の IPv4 埋め込み形式（mapped / translated / compatible / NAT64）・
 * 非グローバル範囲を網羅して拒否し、通常の公開 FQDN / 公開 IP は通すことを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { isPublicHttpsUrl } from '../public-https-url.js';

describe('isPublicHttpsUrl: 公開と判定するもの', () => {
  it.each([
    'https://example.com/',
    'https://issuer.example/manifest',
    'https://sub.domain.example.co.jp:8443/path?q=1',
    'https://xn--eckwd4c7c.xn--zckzah/',
    'https://example.com./',
    'https://8.8.8.8/',
    'https://[2606:4700:4700::1111]/',
    'https://[::ffff:8.8.8.8]/',
    'https://[::ffff:0:8.8.8.8]/',
    'https://[64:ff9b::808:808]/',
  ])('%s', (url) => {
    expect(isPublicHttpsUrl(url)).toBe(true);
  });
});

describe('isPublicHttpsUrl: 非公開と判定するもの', () => {
  it.each([
    // スキーム
    'http://example.com/',
    'ftp://example.com/',
    'not a url',
    // ドット無しの単一ラベル
    'https://intranet/',
    'https://router/',
    'https://intranet./',
    // 予約・内部用 TLD
    'https://localhost/',
    'https://a.localhost/',
    'https://printer.local/',
    'https://svc.internal/',
    'https://nas.lan/',
    'https://printer.home.arpa/',
    'https://corp.intranet/',
    'https://wiki.corp/',
    'https://tv.home/',
    'https://x.private/',
    'https://host.localdomain/',
    'https://1.0.0.127.in-addr.arpa/',
    'https://NAS.LAN/',
    // 数字入りの TLD（IP 表記の取りこぼし）
    'https://example.123/',
    // IPv4（表記ゆれ含む）
    'https://127.0.0.1/',
    'https://0x7f.1/',
    'https://2130706433/',
    'https://10.0.0.1/',
    'https://169.254.169.254/',
    'https://192.168.1.10/',
    'https://172.16.0.1/',
    'https://100.64.0.1/',
    'https://224.0.0.1/',
    // IPv6 非公開範囲
    'https://[::]/',
    'https://[::1]/',
    'https://[fc00::1]/',
    'https://[fd12:3456::1]/',
    'https://[fe80::1]/',
    'https://[fec0::1]/',
    'https://[ff02::1]/',
    'https://[100::1]/',
    'https://[2001:db8::1]/',
    'https://[2001::1]/',
    'https://[2002:7f00:1::1]/',
    'https://[3fff::1]/',
    // IPv4 埋め込み形式（埋め込み先が非公開）
    'https://[::ffff:127.0.0.1]/',
    'https://[::ffff:7f00:1]/',
    'https://[::ffff:0:127.0.0.1]/',
    'https://[::ffff:0:a9fe:a9fe]/',
    'https://[::127.0.0.1]/',
    'https://[::7f00:1]/',
    'https://[64:ff9b::7f00:1]/',
    'https://[64:ff9b::10.0.0.1]/',
    // 局所用 NAT64（RFC 8215）は埋め込み先に関わらず拒否
    'https://[64:ff9b:1::a9fe:a9fe]/',
    'https://[64:ff9b:1::808:808]/',
  ])('%s', (url) => {
    expect(isPublicHttpsUrl(url)).toBe(false);
  });
});
