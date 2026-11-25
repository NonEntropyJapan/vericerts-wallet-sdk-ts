/**
 * KeyManager の KDF パラメータポリシー検証。
 * constructor での不正 KDF 拒否（1051）と、decrypt 経路での偽エンベロープ KDF 拒否（1050、認証前 DoS 対策）。
 * 暗号化↔復号の往復・AAD・salt・短い ct 等の「エンベロープ I/O」基本系は ../keymanager.encrypt.test.ts 側に置く。
 */

import { beforeAll, describe, expect, it } from 'bun:test';
import type { ErrorCode } from '../../../errors.js';
import { VericertsError } from '../../../errors.js';
import type { KdfParams } from '../../kdf.js';
import { KeyManager } from '../../keymanager.js';
import { KDF_TIMEOUT_MS, PRE_KDF_TIMEOUT_MS } from './kdf-timeout.js';

const PASSWORD = 'correct horse battery staple';
/** ソルトは 256 bit（32 バイト）。 */
const SALT_LENGTH = 32;
const IV_LENGTH = 12;
/** V2 エンベロープのヘッダ長: version(1) + kdfJsonLen(2 BE)。 */
const V2_HEADER_LENGTH = 1 + 2;

/** 最小許可プロファイル argon2id（OWASP 最低コスト最軽量: m=9216 && t=4。許可範囲内で高速化）。 */
const MIN_ARGON2ID: KdfParams = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 };
/** K4 既定相当の argon2id（m=19456, t=2, p=1）。 */
const DEFAULT_ARGON2ID: KdfParams = { algo: 'argon2id', version: 1, m: 19456, t: 2, p: 1 };
/** 最小許可プロファイル scrypt（N=2^14, r=8, p=1。許可範囲の最軽量でディスパッチ回帰を守る）。 */
const MIN_SCRYPT: KdfParams = { algo: 'scrypt', version: 1, N: 1 << 14, r: 8, p: 1 };
/** 最小許可プロファイル pbkdf2（iterations=600000。許可下限でディスパッチ回帰を守る）。 */
const MIN_PBKDF2: KdfParams = { algo: 'pbkdf2', version: 1, iterations: 600_000 };

/** VericertsError の code を assert するヘルパ。 */
async function expectRejectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  try {
    await promise;
    throw new Error('expected rejection');
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code);
  }
}

/** 同期 throw が VericertsError かつ指定 code であることを assert するヘルパ。 */
function expectThrowCode(fn: () => unknown, code: ErrorCode): void {
  try {
    fn();
    throw new Error('expected throw');
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code);
  }
}

/**
 * 正常 encrypt 出力の kdfJson 部（生バイト）を差し替えた偽エンベロープを組み立てる。
 * 実 encrypt の salt/iv/ct を再利用し kdfJson と長ヘッダのみ整合差し替えする（モック禁止）。
 */
function withReplacedKdfJsonBytes(envelope: Uint8Array, kdfJson: Uint8Array): Uint8Array {
  const oldLen = ((envelope[1] ?? 0) << 8) | (envelope[2] ?? 0);
  const rest = envelope.subarray(V2_HEADER_LENGTH + oldLen);
  const out = new Uint8Array(V2_HEADER_LENGTH + kdfJson.length + rest.length);
  out[0] = 0x02;
  out[1] = (kdfJson.length >> 8) & 0xff;
  out[2] = kdfJson.length & 0xff;
  out.set(kdfJson, V2_HEADER_LENGTH);
  out.set(rest, V2_HEADER_LENGTH + kdfJson.length);
  return out;
}

/** kdfJson を別の JSON オブジェクトへ差し替えた偽エンベロープを組み立てる。 */
function withReplacedKdfJson(envelope: Uint8Array, replacement: object): Uint8Array {
  return withReplacedKdfJsonBytes(envelope, new TextEncoder().encode(JSON.stringify(replacement)));
}

describe('KeyManager KDF ハードニング（認証前 DoS 対策）', () => {
  // 偽エンベロープは正常 encrypt 出力の kdfJson のみ差し替え（実 KDF）。不正は鍵導出前に 1050 で弾く。
  const cases: ReadonlyArray<{ name: string; kdf: object }> = [
    { name: '巨大 m', kdf: { algo: 'argon2id', version: 1, m: 1 << 30, t: 2, p: 1 } },
    { name: '巨大 N', kdf: { algo: 'scrypt', version: 1, N: 1 << 25, r: 8, p: 1 } },
    { name: '巨大 iter', kdf: { algo: 'pbkdf2', version: 1, iterations: 1e9 } },
    { name: '非整数 m', kdf: { algo: 'argon2id', version: 1, m: 19456.5, t: 2, p: 1 } },
    { name: 'version!=1', kdf: { algo: 'argon2id', version: 2, m: 19456, t: 2, p: 1 } },
    { name: 'N 非冪乗', kdf: { algo: 'scrypt', version: 1, N: 100000, r: 8, p: 1 } },
    { name: 'm<8p', kdf: { algo: 'argon2id', version: 1, m: 8, t: 4, p: 4 } },
    { name: 'OWASP 未達', kdf: { algo: 'argon2id', version: 1, m: 19456, t: 1, p: 1 } },
    { name: 'unknown field', kdf: { algo: 'argon2id', version: 1, m: 19456, t: 2, p: 1, evil: 1 } },
    { name: 't 上限超', kdf: { algo: 'argon2id', version: 1, m: 65536, t: 5, p: 1 } },
    { name: 'm 上限超', kdf: { algo: 'argon2id', version: 1, m: 65537, t: 2, p: 1 } },
  ];

  // 以下のケースは「不正 kdfJson が鍵導出より前に弾かれる」ことだけを主張する。実 encrypt
  // （= 実 argon2id 導出）は準備でしかなく、11 ケースとも KeyManager(MIN_ARGON2ID) と平文が
  // 同一なので 1 本のエンベロープを共有すれば足りる。withReplacedKdfJson は新しい Uint8Array を
  // 返して元を破壊しないため、共有してもケース間は独立する。
  // 準備をケース本体から追い出すことで、各ケースの短い予算（PRE_KDF_TIMEOUT_MS）が
  // 「導出前に弾かれた」ことの検証として実際に機能する（以前は準備の実 KDF が
  // 予算の 99.8% を占め、負荷次第で超過して flaky になっていた）。
  let sharedKm: KeyManager;
  let sharedEnvelope: Uint8Array;

  beforeAll(async () => {
    sharedKm = new KeyManager({ kdf: MIN_ARGON2ID });
    sharedEnvelope = await sharedKm.encrypt(new TextEncoder().encode('dos'), PASSWORD);
  }, KDF_TIMEOUT_MS);

  for (const { name, kdf } of cases) {
    it(
      `偽 KDF（${name}）は鍵導出前に 1050 で reject される`,
      async () => {
        const tampered = withReplacedKdfJson(sharedEnvelope, kdf);
        await expectRejectCode(sharedKm.decrypt(tampered, PASSWORD), '1050');
      },
      PRE_KDF_TIMEOUT_MS,
    );
  }

  it(
    '短い ct(15B、GCM タグ未満)は鍵導出前に 1050 で reject される',
    async () => {
      // ct 長の検査も鍵導出前なので、平文に依らないヘッダ部だけ共有エンベロープから借りる。
      const kdfJsonLen = ((sharedEnvelope[1] ?? 0) << 8) | (sharedEnvelope[2] ?? 0);
      // ct を GCM タグ 16B 未満（15B）にした偽エンベロープを構築する。
      const head = V2_HEADER_LENGTH + kdfJsonLen + SALT_LENGTH + IV_LENGTH;
      const tampered = new Uint8Array(head + 15);
      tampered.set(sharedEnvelope.subarray(0, head), 0);
      await expectRejectCode(sharedKm.decrypt(tampered, PASSWORD), '1050');
    },
    PRE_KDF_TIMEOUT_MS,
  );

  it(
    'AAD 改ざん（許容内の別 KDF へ差し替え）は GCM タグ不一致で 1050',
    async () => {
      // 許容内の別値へ len 整合差し替えすると parseKdf は通るが AAD が変わり GCM タグ不一致で 1050。
      // parseKdf を通る以上この経路は実 KDF 導出を伴うため、短い予算は使えない。
      const km = new KeyManager({ kdf: DEFAULT_ARGON2ID });
      const envelope = await km.encrypt(new TextEncoder().encode('aad bind'), PASSWORD);
      const tampered = withReplacedKdfJson(envelope, MIN_ARGON2ID);
      await expectRejectCode(km.decrypt(tampered, PASSWORD), '1050');
    },
    KDF_TIMEOUT_MS,
  );
});

describe('KeyManager constructor 不正 KDF 拒否', () => {
  it('m<8p の argon2id 注入は constructor で 1051', () => {
    expectThrowCode(
      () => new KeyManager({ kdf: { algo: 'argon2id', version: 1, m: 1, t: 1, p: 1 } }),
      '1051',
    );
  });

  it('version!=1 の注入は constructor で 1051', () => {
    expectThrowCode(
      () => new KeyManager({ kdf: { algo: 'argon2id', version: 2, m: 19456, t: 2, p: 1 } }),
      '1051',
    );
  });

  it('scrypt 非冪乗 N の注入は constructor で 1051', () => {
    expectThrowCode(
      () => new KeyManager({ kdf: { algo: 'scrypt', version: 1, N: 100000, r: 8, p: 1 } }),
      '1051',
    );
  });

  // algo 別に unknown field(evil) を注入すると exact-key 不一致で constructor が 1051 拒否する。
  const unknownFieldCases: ReadonlyArray<{ name: string; base: KdfParams }> = [
    { name: 'argon2id', base: MIN_ARGON2ID },
    { name: 'scrypt', base: MIN_SCRYPT },
    { name: 'pbkdf2', base: MIN_PBKDF2 },
  ];
  for (const { name, base } of unknownFieldCases) {
    it(`${name} に unknown field(evil) を注入すると constructor で 1051`, () => {
      expectThrowCode(
        () => new KeyManager({ kdf: { ...base, evil: 1 } as unknown as KdfParams }),
        '1051',
      );
    });
  }

  it(
    '構築後に元参照を改変しても保持パラメータは不変（TOCTOU 防御）',
    async () => {
      // encrypt と decrypt で実 KDF 導出を 2 回通るため、既定の予算では負荷時に不足しうる。
      // 構築時に正規化済みコピーを保持するため、構築後の元参照の改変は encrypt に影響しない。
      const p: KdfParams = { ...MIN_ARGON2ID };
      const km = new KeyManager({ kdf: p });
      (p as { m: number; t: number }).m = 1 << 30;
      (p as { m: number; t: number }).t = 1;
      const plaintext = new TextEncoder().encode('toctou guard');
      const envelope = await km.encrypt(plaintext, PASSWORD);
      // 保存された kdfJson の m/t は当初値（9216/4）であり巨大値(1<<30)ではない。
      const kdfJsonLen = ((envelope[1] ?? 0) << 8) | (envelope[2] ?? 0);
      const kdfJson = envelope.subarray(V2_HEADER_LENGTH, V2_HEADER_LENGTH + kdfJsonLen);
      const stored = JSON.parse(new TextDecoder().decode(kdfJson)) as { m: number; t: number };
      expect(stored.m).toBe(9216);
      expect(stored.t).toBe(4);
      // 当初パラメータで暗号化された証左として既定 KeyManager で復号し平文一致を確認する。
      const decrypted = await new KeyManager().decrypt(envelope, PASSWORD);
      expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
    },
    KDF_TIMEOUT_MS,
  );
});
