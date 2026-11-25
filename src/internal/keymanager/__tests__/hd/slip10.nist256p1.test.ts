/**
 * SLIP-0010 NIST P-256（`"Nist256p1 seed"`）導出を、規格公開のテストベクタで検証する。
 *
 * ベクタの出典: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
 * 「Test vector 1/2 for nist256p1」「Test derivation retry for nist256p1」「Test seed retry for nist256p1」。
 */

import { describe, expect, it } from 'bun:test';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { deriveSlip10Nist256p1, p256DidPath } from '../../derivation/slip10.js';
import { deriveKeyFromSeed } from '../../hd.js';

interface Vector {
  readonly path: string;
  readonly chainCode: string;
  readonly privateKey: string;
  readonly publicKey: string;
}

const SEED_1 = '000102030405060708090a0b0c0d0e0f';
const SEED_2 =
  'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542';

const VECTOR_1: readonly Vector[] = [
  {
    path: 'm',
    chainCode: 'beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea',
    privateKey: '612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2',
    publicKey: '0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8',
  },
  {
    path: "m/0'",
    chainCode: '3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11',
    privateKey: '6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c',
    publicKey: '0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c',
  },
  {
    path: "m/0'/1",
    chainCode: '4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c',
    privateKey: '284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129',
    publicKey: '03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844',
  },
  {
    path: "m/0'/1/2'",
    chainCode: '98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318',
    privateKey: '694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7',
    publicKey: '0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0',
  },
  {
    path: "m/0'/1/2'/2",
    chainCode: 'ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0',
    privateKey: '5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa',
    publicKey: '029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20',
  },
  {
    path: "m/0'/1/2'/2/1000000000",
    chainCode: 'b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059',
    privateKey: '21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119',
    publicKey: '02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4',
  },
];

const VECTOR_2: readonly Vector[] = [
  {
    path: 'm',
    chainCode: '96cd4465a9644e31528eda3592aa35eb39a9527769ce1855beafc1b81055e75d',
    privateKey: 'eaa31c2e46ca2962227cf21d73a7ef0ce8b31c756897521eb6c7b39796633357',
    publicKey: '02c9e16154474b3ed5b38218bb0463e008f89ee03e62d22fdcc8014beab25b48fa',
  },
  {
    path: 'm/0',
    chainCode: '84e9c258bb8557a40e0d041115b376dd55eda99c0042ce29e81ebe4efed9b86a',
    privateKey: 'd7d065f63a62624888500cdb4f88b6d59c2927fee9e6d0cdff9cad555884df6e',
    publicKey: '039b6df4bece7b6c81e2adfeea4bcf5c8c8a6e40ea7ffa3cf6e8494c61a1fc82cc',
  },
  {
    path: "m/0/2147483647'",
    chainCode: 'f235b2bc5c04606ca9c30027a84f353acf4e4683edbd11f635d0dcc1cd106ea6',
    privateKey: '96d2ec9316746a75e7793684ed01e3d51194d81a42a3276858a5b7376d4b94b9',
    publicKey: '02f89c5deb1cae4fedc9905f98ae6cbf6cbab120d8cb85d5bd9a91a72f4c068c76',
  },
  {
    path: "m/0/2147483647'/1",
    chainCode: '7c0b833106235e452eba79d2bdd58d4086e663bc8cc55e9773d2b5eeda313f3b',
    privateKey: '974f9096ea6873a915910e82b29d7c338542ccde39d2064d1cc228f371542bbc',
    publicKey: '03abe0ad54c97c1d654c1852dfdc32d6d3e487e75fa16f0fd6304b9ceae4220c64',
  },
  {
    path: "m/0/2147483647'/1/2147483646'",
    chainCode: '5794e616eadaf33413aa309318a26ee0fd5163b70466de7a4512fd4b1a5c9e6a',
    privateKey: 'da29649bbfaff095cd43819eda9a7be74236539a29094cd8336b07ed8d4eff63',
    publicKey: '03cb8cb067d248691808cd6b5a5a06b48e34ebac4d965cba33e6dc46fe13d9b933',
  },
  {
    path: "m/0/2147483647'/1/2147483646'/2",
    chainCode: '3bfb29ee8ac4484f09db09c2079b520ea5616df7820f071a20320366fbe226a7',
    privateKey: 'bb0a77ba01cc31d77205d51d08bd313b979a71ef4de9b062f8958297e746bd67',
    publicKey: '020ee02e18967237cf62672983b253ee62fa4dd431f8243bfeccdf39dbe181387f',
  },
];

/** 子鍵導出の無効鍵再試行（`I_L >= n`）が起きるベクタ（SLIP-0010「Test derivation retry」）。 */
const DERIVATION_RETRY: readonly Vector[] = [
  {
    path: "m/28578'",
    chainCode: 'e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2',
    privateKey: '06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669',
    publicKey: '02519b5554a4872e8c9c1c847115363051ec43e93400e030ba3c36b52a3e70a5b7',
  },
  {
    path: "m/28578'/33941",
    chainCode: '9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071',
    privateKey: '092154eed4af83e078ff9b84322015aefe5769e31270f62c3f66c33888335f3a',
    publicKey: '0235bfee614c0d5b2cae260000bb1d0d84b270099ad790022c1ae0b2e782efe120',
  },
];

function expectVectors(seedHex: string, vectors: readonly Vector[]): void {
  for (const vector of vectors) {
    const key = deriveSlip10Nist256p1(hexToBytes(seedHex), vector.path);
    expect(bytesToHex(key.privateKey)).toBe(vector.privateKey);
    expect(bytesToHex(key.publicKey)).toBe(vector.publicKey);
    expect(bytesToHex(key.chainCode)).toBe(vector.chainCode);
    expect(key.derivationPath).toBe(vector.path);
  }
}

describe('SLIP-0010 nist256p1 公式テストベクタ', () => {
  it('Test vector 1（seed 000102…0f、hardened と通常の子鍵）', () => {
    expectVectors(SEED_1, VECTOR_1);
  });

  it('Test vector 2（64 バイト seed、2^31-1 の hardened を含む）', () => {
    expectVectors(SEED_2, VECTOR_2);
  });

  it('子鍵が無効（I_L >= n）のとき規格どおり 0x01 || I_R || ser32(i) で再試行する', () => {
    expectVectors(SEED_1, DERIVATION_RETRY);
  });

  it('マスター鍵が無効のとき中間ハッシュを seed として再試行する（Test seed retry）', () => {
    const key = deriveSlip10Nist256p1(
      hexToBytes('a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446'),
      'm',
    );
    expect(bytesToHex(key.chainCode)).toBe(
      '7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c',
    );
    expect(bytesToHex(key.privateKey)).toBe(
      '3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f',
    );
    expect(bytesToHex(key.publicKey)).toBe(
      '0383619fadcde31063d8c5cb00dbfe1713f3e6fa169d8541a798752a1c1ca0cb20',
    );
  });
});

describe('deriveSlip10Nist256p1 の入力検証', () => {
  const seed = hexToBytes(SEED_1);

  it('seed 長が 16〜64 バイトの範囲外なら 1040', () => {
    for (const length of [0, 15, 65]) {
      try {
        deriveSlip10Nist256p1(new Uint8Array(length), 'm');
        throw new Error('unreachable');
      } catch (error) {
        expect(error).toBeInstanceOf(VericertsError);
        expect((error as VericertsError).code).toBe(ErrorCodes.DERIVATION_PATH_INVALID);
      }
    }
  });

  it('構文不正・index 範囲外のパスは 1040', () => {
    for (const path of ['', 'x', "m/0'/", "m/-1'", 'm/2147483648', "m/2147483648'", 'm/1.5']) {
      try {
        deriveSlip10Nist256p1(seed, path);
        throw new Error(`unreachable: ${path}`);
      } catch (error) {
        expect(error).toBeInstanceOf(VericertsError);
        expect((error as VericertsError).code).toBe(ErrorCodes.DERIVATION_PATH_INVALID);
      }
    }
  });
});

describe('p256DidPath', () => {
  it("DID 鍵の導出パスは purpose 9256' の全 hardened パスで、レガシー m/44'/60' と交わらない", () => {
    expect(p256DidPath(0)).toBe("m/9256'/0'/0'/0'");
    expect(p256DidPath(7)).toBe("m/9256'/0'/7'/0'");
    expect(p256DidPath(0)).not.toContain("44'/60'");
  });

  it('index が負・非整数・2^31 以上なら 1040', () => {
    for (const index of [-1, 1.5, 2 ** 31, Number.NaN]) {
      expect(() => p256DidPath(index)).toThrow(VericertsError);
    }
  });

  it('同じ seed でも SLIP-0010（Nist256p1）鍵はレガシー BIP-32（secp256k1）鍵と一致しない', () => {
    const legacy = deriveKeyFromSeed(hexToBytes(SEED_1), "m/0'");
    const slip10 = deriveSlip10Nist256p1(hexToBytes(SEED_1), "m/0'");
    expect(bytesToHex(slip10.privateKey)).not.toBe(bytesToHex(legacy.privateKey));
  });
});
