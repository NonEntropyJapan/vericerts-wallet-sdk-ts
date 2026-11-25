/**
 * (Q)EAA Catalogue を Credential Type (`vct`) から参照する。
 *
 * 取得・署名検証済みの Catalogue を `AttestationCatalogueSource` として受け取り、型に対応するエントリを返す。
 * vct が未登録の場合は 10003 `EAA_CATALOGUE_NOT_FOUND` を投げる。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { AttestationCatalogueEntry } from './types.js';

/**
 * 取得済み (Q)EAA Catalogue の参照源。
 *
 * vct をキーに `AttestationCatalogueEntry` を返す（未登録は undefined）。
 * インメモリの `Record` でも、キャッシュ / ストレージバック実装でもよい。
 */
export interface AttestationCatalogueSource {
  /** vct に対応する Catalogue エントリを返す。未登録は undefined。 */
  lookup(vct: string): AttestationCatalogueEntry | undefined;
}

/**
 * `Record<vct, AttestationCatalogueEntry>` から `AttestationCatalogueSource` を構築する。
 *
 * `attestationCatalogue` ストレージや静的カタログをそのまま参照源にできる。
 * 呼び出し側で誤って別 vct のエントリを混入させないよう、`entry.vct` とキーの一致を検査する。
 */
export function createRecordCatalogueSource(
  catalogue: Readonly<Record<string, AttestationCatalogueEntry>>,
): AttestationCatalogueSource {
  return {
    lookup(vct: string): AttestationCatalogueEntry | undefined {
      // 引きも突合も**自身のプロパティに限って**行う（`eudi/wua/wua.ts` の
      // `verifyWalletUnitAttestation` と同クラス）。`catalogue` は呼び出し側が組み立てて渡す
      // 対応表なので、鎖読みには 2 つの破れがあった。
      // - `catalogue[vct]`: `vct` が `toString` 等のとき `Object.prototype` のメンバが引ける。
      //   ただし単独では直後の突合が弾くため、**`Object.prototype.vct = 'toString'` の汚染と
      //   併用したとき**に「登録済みエントリ」として通る。
      // - `entry.vct`: own に `vct` を持たないエントリを汚染値で突合させ、**キーと中身が
      //   食い違うエントリを登録済みとして通す**（この突合はまさにそれを防ぐ検査である）。
      const entry = ownProperty<unknown>(catalogue, vct);
      // 読み取った値は `as` でキャストせず形状を検査する（`own-property.ts` の方針）。
      // own の値が `null` のカタログでは、検査を挟まないと次行の `Object.hasOwn(null, 'vct')` が
      // **生の TypeError** を投げて 10003 の契約から外れる。
      if (typeof entry !== 'object' || entry === null) {
        return undefined;
      }
      // キーとエントリの vct が食い違うカタログは信頼せず未登録扱いにする。
      return ownProperty<string>(entry, 'vct') === vct
        ? (entry as AttestationCatalogueEntry)
        : undefined;
    },
  };
}

/**
 * vct を (Q)EAA Catalogue で解決し、対応する `AttestationCatalogueEntry` を返す。
 *
 * `resolveAttestationCatalogue(vct)` の内部実装。vct が Catalogue 未登録の場合は
 * 10003 `EAA_CATALOGUE_NOT_FOUND` を投げる。
 *
 * @param source 取得済み Catalogue の参照源。
 * @param vct    解決対象の VC Type URI。
 */
export function resolveAttestationCatalogue(
  source: AttestationCatalogueSource,
  vct: string,
): AttestationCatalogueEntry {
  const entry = source.lookup(vct);
  if (entry === undefined) {
    // context に vct を含めない（PII ではないが、error-registry の方針に合わせ静的メッセージのみ）。
    throw new VericertsError(ErrorCodes.EAA_CATALOGUE_NOT_FOUND);
  }
  return entry;
}
