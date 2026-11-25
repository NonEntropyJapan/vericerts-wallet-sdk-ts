/**
 * 委任 DID による VC の発行者署名のコンフォーマンスベクタ。W3C DID Core だけで表す（独自クレーム・独自 VC 型なし）。
 *
 * 管理者の個人 DID `P`（鍵 `K`）が、法人 DID `D` として VC に署名する。`D` の DID Document の `assertionMethod` に `K` と同じ公開鍵の
 * 検証メソッド `V` が載っていれば、VC は `iss` = `D`、JWS `kid` = `V` で署名され、検証側は `D` の `assertionMethod` だけで通る。
 *
 * - `delegated-key-select`（署名側）: `D` の文書から、`P` が `D` として署名できるか、署名に使う検証メソッド `V`（`kid`）と `alg` を決める。
 *   controller 関係（`controller` / `capabilityDelegation`）と `K` の検証関係（`assertionMethod`）を両方見る。
 * - `vc-verify-did`（検証側）: JWT-VC の `iss` を `didDocuments` から引き、`assertionMethod` の `kid` の鍵で署名を検証する。
 *   **controller は見ない**（`iss` の文書の `assertionMethod` と JWS `kid` だけ）。
 *
 * 入力の `didDocuments` は「DID → DID Document」の固定表で、ネットワーク解決の代わりに使う。表に無い DID は解決失敗（`2003`）。
 */

import { verifyDelegatedKey } from '../../src/internal/credential/did-signing/delegation.js';
import { issueCredential } from '../../src/internal/credential/vc/issue.js';
import { decodeCompactJws } from '../../src/internal/credential/vc/jws.js';
import { createPrivateKeySigner } from '../../src/internal/credential/vc/signer.js';
import type { VerifiableCredential } from '../../src/internal/credential/vc/vc.js';
import { verifyCredential } from '../../src/internal/credential/vc/verify.js';
import { ErrorCodes, VericertsError } from '../../src/internal/errors.js';
import type { DidResolverLike } from '../../src/internal/identity/bounded-resolver.js';
import type { DIDDocument } from '../../src/internal/identity/did.js';
import { createDidJwk } from '../../src/internal/identity/jwk/method-jwk.js';
import { resolveIssuerVerifierKey } from '../../src/wallet/issuer-key.js';
import type { Case } from './shared.js';

const NOW = 1_767_225_600; // 2026-01-01T00:00:00Z
const CORP = 'did:web:corp.example'; // 委任先（法人）DID `D`
const MEMBER = 'did:jwk:conformance-member'; // VC の主体（メンバー）。解決はしない
const EMBEDDED_KID = `${CORP}#agent-1`;
const OTHER_KID = `${CORP}#other-1`;

type Docs = Record<string, DIDDocument>;

const signer = createPrivateKeySigner(new Uint8Array(32).fill(11), 'ES256');
const otherSigner = createPrivateKeySigner(new Uint8Array(32).fill(17), 'ES256');
const personaDocument = createDidJwk(signer.publicKeyJwk);
const PERSONA = personaDocument.id; // 管理者の個人 DID `P`（did:jwk）
const PERSONA_KID = `${PERSONA}#0`;

function embeddedMethod(id: string, jwk: object, controller = CORP): Record<string, unknown> {
  return { id, type: 'JsonWebKey2020', controller, publicKeyJwk: jwk };
}

/** 委任先 `D` の DID Document。`overrides` で個別のフィールドを差し替える。 */
function corpDocument(overrides: Record<string, unknown> = {}): DIDDocument {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: CORP,
    controller: [PERSONA],
    verificationMethod: [embeddedMethod(EMBEDDED_KID, signer.publicKeyJwk)],
    authentication: [EMBEDDED_KID],
    assertionMethod: [EMBEDDED_KID],
    ...overrides,
  } as unknown as DIDDocument;
}

function resolverOf(docs: Docs): DidResolverLike {
  return {
    resolve: async (did) => {
      const document = docs[did];
      if (document === undefined) throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
      return document;
    },
  };
}

function memberVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: CORP,
    credentialSubject: { id: MEMBER, name: 'Conformance Member' },
    issuanceDate: '2025-12-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
  };
}

/** `kid` を指定した JWT-VC を `signWith` で署名する（`iss` = `D`）。 */
function sign(kid: string | undefined, signWith = signer): string {
  return issueCredential(
    memberVc(),
    { ...signWith, ...(kid !== undefined ? { kid } : {}) },
    {
      nowSeconds: NOW - 1000,
    },
  );
}

/** 検証側の規則（`iss` の文書の `assertionMethod` と `kid`）で JWT-VC を検証する。 */
async function verifyViaDocuments(token: string, docs: Docs): Promise<void> {
  const key = await resolveIssuerVerifierKey(resolverOf(docs), token);
  verifyCredential(token, { key, nowSeconds: NOW });
}

/** `run` が成功すれば `undefined`、`VericertsError` で失敗すればその code。それ以外の例外は fail-closed で投げ直す。 */
async function failureCodeOf(run: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await run();
  } catch (e) {
    if (e instanceof VericertsError) return e.code;
    throw e;
  }
  return undefined;
}

async function verifyCase(
  id: string,
  description: string,
  token: string,
  docs: Docs,
): Promise<Case> {
  const errorCode = await failureCodeOf(() => verifyViaDocuments(token, docs));
  const { header, payload } = decodeCompactJws(token);
  return {
    id,
    category: 'vc-verify-did',
    description,
    input: { format: 'jwt-vc', token, didDocuments: docs, nowSeconds: NOW },
    expected:
      errorCode === undefined
        ? { ok: true, iss: payload.iss, kid: header.kid }
        : { ok: false, errorCode },
  };
}

async function selectCase(
  id: string,
  description: string,
  docs: Docs,
  opts: { relationship: 'authentication' | 'assertionMethod'; kid?: string },
): Promise<Case> {
  const key = {
    delegatedDid: CORP,
    controllerDid: PERSONA,
    relationship: opts.relationship,
    ...(opts.kid !== undefined ? { kid: opts.kid } : {}),
  };
  let expected: Record<string, unknown>;
  try {
    const match = await verifyDelegatedKey(resolverOf(docs), key, signer.publicKeyJwk);
    expected = { ok: true, kid: match.kid, alg: match.alg, basis: match.basis };
  } catch (e) {
    if (!(e instanceof VericertsError)) throw e;
    expected = { ok: false, errorCode: e.code };
  }
  return {
    id,
    category: 'delegated-key-select',
    description,
    input: { ...key, publicKeyJwk: signer.publicKeyJwk, didDocuments: docs },
    expected,
  };
}

export async function getDelegatedVcCases(): Promise<Case[]> {
  const cases: Case[] = [];
  const embedded: Docs = { [CORP]: corpDocument() };
  const reference: Docs = {
    [CORP]: corpDocument({
      verificationMethod: [],
      authentication: [PERSONA_KID],
      assertionMethod: [PERSONA_KID],
    }),
    [PERSONA]: personaDocument,
  };

  // --- 検証側（controller は見ない。`iss` の文書の `assertionMethod` と JWS `kid` だけ） ---
  cases.push(
    await verifyCase(
      'delegated-vc-verify-embedded-assertion-method',
      'VC signed as the corporate DID verifies via a key embedded in its assertionMethod (iss = D, kid = D#agent-1)',
      sign(EMBEDDED_KID),
      embedded,
    ),
    await verifyCase(
      'delegated-vc-verify-referenced-assertion-method',
      "VC verifies when D.assertionMethod references the persona's verification method by DID URL (the referenced DID is resolved)",
      sign(PERSONA_KID),
      reference,
    ),
    await verifyCase(
      'delegated-vc-verify-ignores-controller',
      'Verification reads only assertionMethod and kid: D without any controller still verifies',
      sign(EMBEDDED_KID),
      { [CORP]: corpDocument({ controller: [] }) },
    ),
    await verifyCase(
      'delegated-vc-verify-authentication-only-rejected',
      'A key listed only in authentication is not an assertionMethod key: rejected (2010)',
      sign(EMBEDDED_KID),
      { [CORP]: corpDocument({ assertionMethod: [] }) },
    ),
    await verifyCase(
      'delegated-vc-verify-kid-outside-assertion-method',
      'kid naming a verification method that is not in assertionMethod is rejected (2010), even if another assertionMethod key exists',
      sign(OTHER_KID),
      {
        [CORP]: corpDocument({
          verificationMethod: [
            embeddedMethod(EMBEDDED_KID, otherSigner.publicKeyJwk),
            embeddedMethod(OTHER_KID, signer.publicKeyJwk),
          ],
          authentication: [EMBEDDED_KID, OTHER_KID],
          assertionMethod: [EMBEDDED_KID],
        }),
      },
    ),
    await verifyCase(
      'delegated-vc-verify-key-mismatch',
      'Signature by a key that is not the one listed under kid is rejected (3010)',
      sign(EMBEDDED_KID, otherSigner),
      embedded,
    ),
    await verifyCase(
      'delegated-vc-verify-deactivated-delegated-did',
      'A deactivated D has no usable keys: rejected (2010)',
      sign(EMBEDDED_KID),
      { [CORP]: corpDocument({ deactivated: true }) },
    ),
    await verifyCase(
      'delegated-vc-verify-reference-unresolvable',
      'D.assertionMethod references the persona DID but its document cannot be resolved: rejected (2003)',
      sign(PERSONA_KID),
      { [CORP]: reference[CORP] },
    ),
    await verifyCase(
      'delegated-vc-verify-reference-controller-mismatch',
      'A referenced verification method whose controller is neither itself nor its DID is rejected (2010)',
      sign(PERSONA_KID),
      {
        [CORP]: reference[CORP],
        [PERSONA]: {
          ...personaDocument,
          verificationMethod: [
            embeddedMethod(PERSONA_KID, signer.publicKeyJwk, 'did:web:attacker.example'),
          ],
        } as unknown as DIDDocument,
      },
    ),
  );

  // --- 署名側（controller 関係 + K が assertionMethod に載っていること。署名に使う検証メソッド V の選び方） ---
  cases.push(
    await selectCase(
      'delegated-key-select-embedded-assertion-method',
      'controller lists the persona and K is in assertionMethod: kid = the embedded D#agent-1, basis controller',
      embedded,
      { relationship: 'assertionMethod' },
    ),
    await selectCase(
      'delegated-key-select-referenced-assertion-method',
      "D.assertionMethod references the persona's method by DID URL: kid is that DID URL",
      reference,
      { relationship: 'assertionMethod', kid: PERSONA_KID },
    ),
    await selectCase(
      'delegated-key-select-capability-delegation',
      'persona is a controller through capabilityDelegation instead of controller: basis capabilityDelegation',
      {
        [CORP]: corpDocument({
          controller: [],
          capabilityDelegation: [
            embeddedMethod(`${CORP}#delegate-1`, signer.publicKeyJwk, PERSONA),
          ],
        }),
      },
      { relationship: 'assertionMethod' },
    ),
    await selectCase(
      'delegated-key-select-authentication-only-rejected',
      'K only in authentication is not enough to sign a VC as D: rejected (2017)',
      { [CORP]: corpDocument({ assertionMethod: [] }) },
      { relationship: 'assertionMethod' },
    ),
    await selectCase(
      'delegated-key-select-not-a-controller',
      'K is in assertionMethod but the persona is not a controller of D: rejected (2006)',
      { [CORP]: corpDocument({ controller: [] }) },
      { relationship: 'assertionMethod' },
    ),
    await selectCase(
      'delegated-key-select-prefers-method-in-both-relationships',
      'two methods carry K: the one in both authentication and assertionMethod is chosen over an earlier assertionMethod-only one',
      {
        [CORP]: corpDocument({
          verificationMethod: [
            embeddedMethod(OTHER_KID, signer.publicKeyJwk),
            embeddedMethod(EMBEDDED_KID, signer.publicKeyJwk),
          ],
          authentication: [EMBEDDED_KID],
          assertionMethod: [OTHER_KID, EMBEDDED_KID],
        }),
      },
      { relationship: 'assertionMethod' },
    ),
  );
  return cases;
}
