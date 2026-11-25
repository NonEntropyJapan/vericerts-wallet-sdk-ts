import { afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test';
import * as root from '../../index.js';
import {
  resetExperimentalWarnings,
  SUPPRESS_EXPERIMENTAL_WARNINGS_ENV,
} from '../../internal/experimental-warning.js';
import { buildReceivedIssuerTrust, type DidResolverLike } from '../eudi.js';
import * as experimentalEudi from '../experimental/eudi.js';
import * as experimentalOid4vci from '../experimental/oid4vci.js';
import * as experimental from '../experimental.js';
import {
  type FetchLike,
  type PreAuthorizedIssuerEndpoints,
  resolvePreAuthorizedTokenEndpoint,
  resolveProofNonce,
} from '../oid4vci.js';
import { isPinnedJwkSet } from '../trust.js';

const ISSUER = 'https://issuer.example.eu';
const AS = 'https://as.example.eu';
const TOKEN = `${AS}/token`;
const LEGACY = `${ISSUER}/legacy-token`;

describe('OID4VCI / EUDI / trust public entries', () => {
  test('AS Metadata takes precedence and the legacy endpoint is used only when unreachable', async () => {
    const issuer = { authorizationServers: [AS], tokenEndpoint: LEGACY } as const;
    const fetchImpl: FetchLike = async () =>
      new Response(JSON.stringify({ issuer: AS, token_endpoint: TOKEN }), {
        headers: { 'Content-Type': 'application/json' },
      });
    expect(await resolvePreAuthorizedTokenEndpoint({}, issuer, ISSUER, fetchImpl)).toEqual({
      tokenEndpoint: TOKEN,
      source: 'authorization_server',
    });
    const unavailable: FetchLike = async () => new Response('', { status: 404 });
    expect(await resolvePreAuthorizedTokenEndpoint({}, issuer, ISSUER, unavailable)).toEqual({
      tokenEndpoint: LEGACY,
      source: 'legacy_issuer_metadata',
    });
    const mismatched: FetchLike = async () =>
      new Response(JSON.stringify({ issuer: ISSUER, token_endpoint: TOKEN }), {
        headers: { 'Content-Type': 'application/json' },
      });
    await expect(
      resolvePreAuthorizedTokenEndpoint({}, issuer, ISSUER, mismatched),
    ).rejects.toMatchObject({
      context: { reason: 'issuer_mismatch' },
    });
  });

  test('nonce endpoint is preferred over the legacy token response nonce', async () => {
    const fetchImpl: FetchLike = async () =>
      new Response(JSON.stringify({ c_nonce: 'endpoint-nonce' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    expect(await resolveProofNonce('legacy-nonce', `${ISSUER}/nonce`, fetchImpl)).toBe(
      'endpoint-nonce',
    );
    expect(await resolveProofNonce('legacy-nonce', undefined, fetchImpl)).toBe('legacy-nonce');
  });

  test('unreachable AS rejects insecure legacy token endpoints', async () => {
    const unavailable: FetchLike = async () => new Response('', { status: 404 });
    for (const tokenEndpoint of [
      'http://issuer.example.eu/token',
      'https://127.0.0.1/token',
      'https://localhost/token',
    ]) {
      await expect(
        resolvePreAuthorizedTokenEndpoint(
          {},
          { authorizationServers: [AS], tokenEndpoint },
          ISSUER,
          unavailable,
        ),
      ).rejects.toMatchObject({
        code: '3004',
        context: { reason: 'non_https_endpoint' },
      });
    }
  });

  test('issuer endpoint inputs ignore inherited AS and legacy token endpoints', async () => {
    const inherited = Object.create({
      authorizationServers: [AS],
      tokenEndpoint: LEGACY,
    }) as PreAuthorizedIssuerEndpoints;
    const seen: string[] = [];
    const fetchImpl: FetchLike = async (url) => {
      seen.push(url);
      return new Response(JSON.stringify({ issuer: ISSUER, token_endpoint: `${ISSUER}/token` }), {
        headers: { 'Content-Type': 'application/json' },
      });
    };
    expect(await resolvePreAuthorizedTokenEndpoint({}, inherited, ISSUER, fetchImpl)).toEqual({
      tokenEndpoint: `${ISSUER}/token`,
      source: 'authorization_server',
    });
    expect(seen[0]).toContain(ISSUER);
    const unavailable: FetchLike = async () => new Response('', { status: 404 });
    await expect(
      resolvePreAuthorizedTokenEndpoint({}, inherited, ISSUER, unavailable),
    ).rejects.toBeDefined();
  });

  test('issuer trust retains own data properties and pinned JWK checks own keys', () => {
    const resolver = {
      resolve: async () => ({ id: 'did:example:issuer' }),
    } as unknown as DidResolverLike;
    const trust = buildReceivedIssuerTrust({}, resolver, undefined);
    expect(Object.hasOwn(trust, 'issuerTrustAnchors')).toBe(true);
    expect(Object.hasOwn(trust, 'jwtVcIssuerMetadataResolution')).toBe(true);
    expect(trust.resolver).toBe(resolver);
    expect(isPinnedJwkSet({ keys: [{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }] })).toBe(true);
    expect(
      isPinnedJwkSet(Object.create({ keys: [{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }] })),
    ).toBe(false);
  });

  test('explicit experimental names use one wrapper and remain absent from root', () => {
    expect(experimental.presentEAACredential).toBe(experimentalEudi.presentEAACredential);
    expect(experimental.presentPIDCredential).toBe(experimentalEudi.presentPIDCredential);
    expect(experimental.receiveVerifiedEAA).toBe(experimentalEudi.receiveVerifiedEAA);
    expect(experimental.receiveVerifiedPID).toBe(experimentalEudi.receiveVerifiedPID);
    for (const name of [
      'presentEAACredential',
      'presentPIDCredential',
      'receiveVerifiedEAA',
      'receiveVerifiedPID',
    ] as const) {
      expect((root as Record<string, unknown>)[name]).toBeUndefined();
    }
    expect(experimental.fetchIssuerMetadata).toBe(experimentalOid4vci.fetchIssuerMetadata);
    expect((root as Record<string, unknown>).fetchIssuerMetadata).toBeUndefined();
  });
});

describe('experimental warning shared across both import paths', () => {
  let warn: ReturnType<typeof spyOn<Console, 'warn'>>;
  let previousSuppression: string | undefined;

  beforeEach(() => {
    previousSuppression = process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV];
    delete process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV];
    resetExperimentalWarnings();
    warn = spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warn.mockRestore();
    resetExperimentalWarnings();
    if (previousSuppression === undefined) {
      delete process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV];
    } else {
      process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV] = previousSuppression;
    }
  });

  test('calling one API through two entries warns once', async () => {
    await expect(
      experimentalOid4vci.fetchIssuerMetadata('http://issuer.example.eu'),
    ).rejects.toBeDefined();
    await expect(
      experimental.fetchIssuerMetadata('http://issuer.example.eu'),
    ).rejects.toBeDefined();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0]?.[0]).toContain('fetchIssuerMetadata');
  });
});
