/**
 * Wallet ファサードの `updateDID` の実装。
 *
 * `DidFacade`（`facade.ts`）が 1 行で委譲する。担うのは次の 4 段で、**公開そのものは担わない**。
 *
 * 1. 現行 DID Document を解決する（`Resolver.resolve`）。
 * 2. `UpdateDIDOptions` の差分を適用する（`internal/identity/did-document-patch.ts`）。
 * 3. **この更新で追加される分**に GDPR Art.9 特別カテゴリ属性ガード（`assertNoSpecialCategoryOnChain`、
 *    `10601`）を通す。
 * 4. 公開を DID メソッドプラグインへ委譲する（`Resolver.update` → `DIDMethod.update`）。
 *
 * ## なぜ差分適用とガードをファサード側に置くか
 *
 * 差分の意味（削除→追加の順・存在しない id の扱い・relationship 参照の掃除）と Art.9 ガードは
 * DID メソッドに依らない共通規則である。プラグインごとに実装させると「did:X では削除できたが
 * did:Y では黙って無視された」「新しいプラグインだけ Art.9 検査が抜けた」という差が生まれる。
 * そこで、すべての更新経路に共通するこの段階で検査を行う。各プラグインは受け取った
 * 次版 Document（`UpdateOptions.document`）の公開を担う。
 *
 * ## 署名者の解決について
 *
 * **`updateDID` は署名も送信もしない。** 署名を要する更新の成果物は DID メソッドごとに形が違い、
 * いずれも本 API の戻り値（`Promise<DIDDocument>`）では表現できないためである。
 *
 * - did:webvh の更新は**署名付きハッシュチェーンログの追記**であり、成果物は DID
 *   Document ではなく Log エントリで、`previousLog` と `updateKeys` を呼び出し側が持つ。専用 API
 *   `updateDidWebVh` を使う。
 * - did:ethr の controller 操作は**未署名トランザクションの構築まで**が SDK の責務で、署名と
 *   ブロードキャストは呼び出し側が行う（`buildSetControllerTx` / `buildRemoveControllerTx`）。
 *
 * したがって `UpdateDIDOptions` に `keyID` は持たせない。公開に鍵が要るプラグインは
 * `UpdateOptions` を拡張して自前の材料を受け取る（did:ipid の `ipnsKeyBytes` / `ipnsKeyName` が
 * 既にその形である）。
 *
 * ## `resolveDID` / `getDID` の整合性
 *
 * `getDID` は `createDID` が storage へ書いたローカル控えを返し、`resolveDID` は DID 文字列から
 * 再構築・再取得する。両者が食い違わないよう、本モジュールは**公開が成功した後にだけ**、かつ
 * **既に控えが存在する DID についてだけ**控えを書き戻す。
 *
 * - 公開前に控えを書くと、公開に失敗した Document が `getDID` から見えて `resolveDID` と食い違う。
 * - 控えの無い DID に新しく控えを作ると、`createDID` していない DID が `listDIDs` に現れる。
 * - 不変メソッド（did:key / did:jwk / did:peer / did:pkh / did:jwt）は `DIDMethod.update` が
 *   `2002` を投げるため段 4 を越えられず、控えは書かれない。これらは `resolveDID` が DID 文字列
 *   から決定論的に Document を再構築する（storage を読まない）ので、控えだけを可変にすると
 *   `getDID` と `resolveDID` が恒久的に食い違う。段 4 の `2002` がその構造的な保証である。
 *
 * ## セキュリティ上の注意
 *
 * - `opts` は**そのままプラグインへ渡さない**。`UpdateDIDOptions` の公開メンバを 1 度だけ読んで
 *   畳んだ差分（{@link readDiff}）と `document` だけを載せた新しいオブジェクトを作る
 *   （{@link pluginOptions}）。スプレッドで転送すると、呼び出し側が `document` を直接指定して
 *   差分適用と Art.9 ガードを迂回できるうえ、メソッド固有の公開材料（did:ipid の
 *   `ipnsKeyBytes` / `ipnsKeyName`）が渡って `2002` の拒否を素通りする。
 * - `opts` の各メンバは**段 2 の前に 1 度だけ**読む（{@link readDiff}）。段 2 と段 4 で別々に
 *   読み直すと、own アクセサで実装された `opts` が読むたびに違う値を返し、**Art.9 ガードを通った
 *   値とプラグインへ渡る値が別物**になる（差分を自分で適用するプラグインが未検査の値を公開する）。
 * - プラグインが返した Document の `id` が対象 DID と一致することを**書き戻す前に**確かめる。
 *   別 DID の Document を控えに書くと、`getDID(didA)` が `id: didB` を返すローカル状態の破損になる。
 * - 例外の `context` は固定識別子のみ。DID 文字列・鍵・エンドポイントは載せない。
 */

import { ErrorCodes, VericertsError } from '../../internal/errors.js';
import type {
  DIDDocument,
  Service,
  UpdateOptions,
  VerificationMethod,
} from '../../internal/identity/did.js';
import { applyDidDocumentUpdate } from '../../internal/identity/did-document-patch.js';
import type { Resolver } from '../../internal/identity/resolver.js';
import { deepSnapshot } from '../../internal/prototype-safety/deep-snapshot.js';
import { ownProperty } from '../../internal/prototype-safety/own-property.js';
import { assertNoSpecialCategoryOnChain } from '../../internal/special-category.js';
import type { Storage } from '../../internal/storage-port.js';
import { encodeDocument } from '../codec.js';
import type { UpdateDIDOptions } from './options.js';

/**
 * `UpdateDIDOptions` の 6 メンバを **1 度だけ** own 限定に読み、確定値の plain object へ畳む。
 *
 * 呼び出し側の `opts` は任意のオブジェクトなので、メンバが own アクセサ（`get addService() {…}`）
 * で実装されていることがあり得る。読むたびに違う値を返すアクセサを段 2（差分適用 + Art.9 ガード）
 * と段 4（プラグインへの委譲）でそれぞれ読むと、**ガードが見た値と公開される値が別物になる** —
 * 差分を自分で適用するプラグイン（`opts.document` を見ないプラグイン）は、Art.9 検査を一度も
 * 通っていない特別カテゴリ属性をそのままオンチェーン / DID Log へ載せられる。ここで 1 度だけ
 * 読んだ結果を両段で共有することでその窓を閉じる。
 *
 * **「1 度だけ」なのは読みであって、コピーの数ではない。** 段 2 の `applyDidDocumentUpdate` は
 * 受け取った値を `foldedOrReject` でもう一度畳む（`did-document-patch.ts`）。結果、プラグインは
 * 構造的に等しいが同一ではない 2 つのコピー —— `opts.addService`（本関数が畳んだもの）と
 * `opts.document.service[N]`（Art.9 ガードが実際に走査したもの）—— を受け取る。素の入れ物を
 * 連続してスナップショットしても構造は変わらず、畳めない入力は `foldedOrReject` が拒否するので
 * 安全側は保たれる。`did-document-patch.ts` 側の fold を外さないのは、あちらが「畳めない構造体は
 * `2010` で拒否する」契約（`service_not_foldable` 等）を自分で持つモジュールであり、入力が既に
 * 畳まれているかを呼び出し側に依存させないためである。
 *
 * 追加される構造体は `deepSnapshot` で**入れ子まで**畳む。トップレベルだけ読み直さない形にしても、
 * `addService.serviceEndpoint` のような入れ子の own アクセサが残っていると同じドリフトが深さ 1 以上で
 * 成立するためである（`did-document-patch.ts` / `deep-snapshot.ts` のヘッダ参照）。削除系は DID
 * 文字列・id なので 1 度読むだけでよい。
 *
 * 各メンバは own 限定で読む（`did-document-patch.ts` と同じ理由。鎖読みだと
 * `Object.prototype.addController` の汚染値がプラグインへ流れる）。
 */
function readDiff(opts: UpdateDIDOptions): UpdateDIDOptions {
  return {
    addVerificationMethod: deepSnapshot(
      ownProperty<VerificationMethod>(opts, 'addVerificationMethod'),
    ) as VerificationMethod | undefined,
    removeVerificationMethod: ownProperty<string>(opts, 'removeVerificationMethod'),
    addService: deepSnapshot(ownProperty<Service>(opts, 'addService')) as Service | undefined,
    removeService: ownProperty<string>(opts, 'removeService'),
    addController: ownProperty<string>(opts, 'addController'),
    removeController: ownProperty<string>(opts, 'removeController'),
  };
}

/**
 * プラグインへ渡すオプションを、畳んだ差分（{@link readDiff}）+ `document` に限定して組み立てる。
 *
 * `{ ...opts, document: next }` のスプレッドだと、呼び出し側の own プロパティが**そのまま**
 * プラグインへ転送される。did:ipid の `MethodIpid.update` は `ipnsKeyBytes` / `ipnsKeyName` の
 * 有無で「IPNS 公開モード」を判定するため、`updateDID(did, { ...diff, ipnsKeyBytes })` のような
 * 呼び出しが `2002 METHOD_NOT_SUPPORTED` で止まらず公開まで進んでしまう（fail-open）。しかも
 * `MethodIpid.update` は `opts.document` を見ないので、Art.9 ガードを通した次版 Document ではなく
 * 別物が公開される。ここで**知っているメンバだけ**を移し替えることで、メソッド固有の公開材料は
 * 転送しない。`updateDID` は署名も公開材料の受け渡しも担わない。
 *
 * `diff` は本モジュールが作った plain object なのでスプレッドしてよい（呼び出し側の own
 * プロパティは {@link readDiff} で既に落ちている）。`document` は最後に載せて必ず上書きする。
 */
function pluginOptions(diff: UpdateDIDOptions, document: DIDDocument): UpdateOptions {
  return { ...diff, document };
}

/**
 * 次版 Document のうち**この更新で新しく載った**要素だけを取り出す（Art.9 ガードの走査対象）。
 *
 * `applyDidDocumentUpdate` は既存要素を参照そのままで引き継ぎ（配列の filter）、追加要素だけを
 * `deepSnapshot` した新しいオブジェクトとして末尾に足す。よって参照同一性で「据え置き」と
 * 「追加」を分けられる。opts を読み直さずに `next` から取るのが要点で、own アクセサが読むたびに
 * 違う値を返す入力でも、**実際に公開される値そのもの**を検査できる（読み直すと検査した値と
 * 公開される値が別物になり得る）。
 *
 * controller は DID 文字列なので、属性名を見る Art.9 ガードの対象になり得ない（走査しない）。
 */
function addedContent(current: DIDDocument, next: DIDDocument): readonly unknown[] {
  // 配列メンバは own 限定で読む（`Object.prototype.service` の汚染値を「文書に載っていた要素」として
  // 据え置き扱い・追加扱いにしない）。
  const entriesOf = (
    document: DIDDocument,
    key: 'verificationMethod' | 'service',
  ): readonly unknown[] => ownProperty<readonly unknown[]>(document, key) ?? [];
  const retained = new Set<unknown>([
    ...entriesOf(current, 'verificationMethod'),
    ...entriesOf(current, 'service'),
  ]);
  return [
    ...entriesOf(next, 'verificationMethod').filter((entry) => !retained.has(entry)),
    ...entriesOf(next, 'service').filter((entry) => !retained.has(entry)),
  ];
}

/**
 * DID Document を更新する。
 *
 * @param resolver DID メソッドプラグインの登録先（解決と公開委譲の両方に使う）。
 * @param storage ローカル控えの保存先（`createDID` が書いた分だけを書き戻す）。
 * @param storageKey DID 文字列から storage キーを作る関数（`DidFacade` と同じ規則を共有する）。
 * @param did 更新対象の DID 文字列。
 * @param opts 差分操作。`document` は受け取らない（指定されても {@link readDiff} が落とす）。
 * @returns 公開後の DID Document。
 * @throws DID 形式不正（VericertsError、code `2001`）、未対応・更新非対応の DID メソッド
 *         （`2002`）、解決失敗（`2003`）、差分適用の失敗・公開結果の `id` 不一致（`2010`）、
 *         追加分が Art.9 特別カテゴリ属性を含む場合（`10601`）。
 */
export async function updateDidWith(
  resolver: Resolver,
  storage: Storage,
  storageKey: (did: string) => string,
  did: string,
  opts: UpdateDIDOptions,
): Promise<DIDDocument> {
  const current = await resolver.resolve(did);
  // `opts` を読むのはここだけ。以降の段はすべて `diff` の確定値を共有する（段 2 と段 4 で
  // 読み直すと、own アクセサの `opts` で Art.9 ガードを通った値とプラグインへ渡る値がずれる）。
  const diff = readDiff(opts);
  const next = applyDidDocumentUpdate(current, diff);
  // 公開前に止める（DID Document はオンチェーン / DID Log / 公開 HTTPS へ出ると取り消せない）。
  // 走査対象はこの更新で追加される分だけ。次版 Document 全体を走査すると、
  // (a) 既存の Art.9 属性を削除するための更新まで `10601` で弾かれ、復旧できない。
  // (b) `current` はネットワーク由来なので、Issuer 側ホストを汚染されると更新が永久に DoS される。
  // 「新しく公開される値を Art.9 で止める」という目的には追加分の検査で足りる。
  assertNoSpecialCategoryOnChain(addedContent(current, next));
  // `document` は必ず own プロパティとして載せ、呼び出し側指定の `document` を上書きする。
  // メソッド固有の公開材料（did:ipid の IPNS 鍵など）は `pluginOptions` が落とす。
  const published = await resolver.update(did, pluginOptions(diff, next));
  if (ownProperty<string>(published, 'id') !== did) {
    // プラグインが別 DID の Document を返した場合、書き戻すと `getDID(didA)` が `id: didB` を
    // 返すローカル状態の破損になる。書かずに倒す（`2010` = 更新結果が不正）。
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID, {
      context: { reason: 'published_id_mismatch' },
    });
  }
  const key = storageKey(did);
  if ((await storage.get(key)) !== null) {
    // 控えがある DID だけ書き戻す（`getDID` と `resolveDID` を食い違わせない）。
    await storage.set(key, encodeDocument(published));
  }
  return published;
}
