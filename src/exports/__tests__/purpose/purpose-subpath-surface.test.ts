import { describe, expect, test } from 'bun:test';
import * as sdk from '../../../index';
import * as aaEntry from '../../aa';
import * as assetEntry from '../../asset';
import * as commonEntry from '../../common';
import * as credentialEntry from '../../credential';
import * as eudiEntry from '../../eudi';
import * as gdprEntry from '../../gdpr';
import * as identityEntry from '../../identity';
import * as keymanagerEntry from '../../keymanager';
import * as oid4vciEntry from '../../oid4vci';
import * as oid4vpEntry from '../../oid4vp';
import * as personaEntry from '../../persona';
import * as trustEntry from '../../trust';
import { EXPERIMENTAL_CALLABLES, EXPERIMENTAL_CONSTANTS } from '../experimental-names.fixtures';
import {
  COMMON_SUBPATH_ONLY_VALUES,
  PURPOSE_ENTRIES,
  PURPOSE_ENTRY_VALUES,
  PURPOSE_SUBPATH_ONLY_VALUES,
} from './purpose-entries.fixtures';

/**
 * 用途別 entry（`./aa` … `./trust` の 12 本）の公開サーフェスの契約を固定する回帰テスト。
 *
 * 再公開分はメインと同一参照。 /common、 /oid4vp、 /oid4vci の
 * 追加値、 /aa と /asset の personalSignMessageBytes はサブパス専用である。
 * 値として公開される名前（型は実体が無いので対象外）を一覧で固定し、件数の一致を機械的に確認する。
 * 一覧への足し忘れ・意図しない公開面の増減をここで検出する。
 * exports マップと build 配線は `purpose-subpath-contract.test.ts` が担う。
 */

const PURPOSE_ENTRY_MODULES: Record<(typeof PURPOSE_ENTRIES)[number], Record<string, unknown>> = {
  aa: aaEntry,
  asset: assetEntry,
  common: commonEntry,
  credential: credentialEntry,
  eudi: eudiEntry,
  gdpr: gdprEntry,
  identity: identityEntry,
  keymanager: keymanagerEntry,
  oid4vci: oid4vciEntry,
  oid4vp: oid4vpEntry,
  persona: personaEntry,
  trust: trustEntry,
};

const addedValues: Readonly<Record<string, readonly string[]>> = {
  aa: ['ENTRY_POINT_V07_ADDRESS', 'signUserOpWithPasskey'],
  asset: ['personalSignMessageBytes'],
  oid4vci: ['resolvePreAuthorizedTokenEndpoint', 'resolveProofNonce'],
};

describe('purpose-built subpath contract: public surface', () => {
  for (const name of PURPOSE_ENTRIES) {
    test(`./${name} keeps the exact set of value exports`, () => {
      expect(Object.keys(PURPOSE_ENTRY_MODULES[name]).sort()).toEqual([
        ...PURPOSE_ENTRY_VALUES[name],
      ]);
    });

    // bun test はソースを読むため、同一モジュールの再エクスポートの toBe はほぼ自明になる。
    // ここで検出できるのは `export *` の名前衝突でメインから脱落した場合程度。
    // ビルド成果物でのクラス・状態の同一性は smoke-node.{mjs,cjs} が担保する。
    test(`./${name} shares references with the main barrel (source level; built artifacts are covered by smoke-node) and leaks no experimental names`, () => {
      const main = sdk as unknown as Record<string, unknown>;
      const experimentalNames = [
        ...EXPERIMENTAL_CALLABLES,
        ...Object.keys(EXPERIMENTAL_CONSTANTS),
      ] as string[];
      const subpathOnly = new Set<string>(
        name === 'common'
          ? COMMON_SUBPATH_ONLY_VALUES
          : name === 'oid4vp'
            ? PURPOSE_SUBPATH_ONLY_VALUES.oid4vp
            : (addedValues[name] ?? []),
      );
      for (const key of PURPOSE_ENTRY_VALUES[name]) {
        if (subpathOnly.has(key)) {
          expect(main).not.toHaveProperty(key);
        } else {
          expect(PURPOSE_ENTRY_MODULES[name][key]).toBe(main[key]);
        }
        expect(experimentalNames).not.toContain(key);
      }
    });
  }
});
