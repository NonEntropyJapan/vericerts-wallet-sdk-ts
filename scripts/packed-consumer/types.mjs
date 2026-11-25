import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { didResourcesTypeFixture } from './did-resources-types.mjs';

export function checkTypes(pkg, consumer, run, withOtel) {
  const specifiers = Object.keys(pkg.exports).filter(
    (name) => name !== './package.json' && (withOtel || name !== './otel'),
  );
  const source =
    specifiers
      .map(
        (name, i) =>
          `import * as e${i} from '${name === '.' ? pkg.name : `${pkg.name}/${name.slice(2)}`}';\nvoid e${i};`,
      )
      .join('\n') +
    `\nimport { VericertsError as MainError, KeyManager as MainKey, PersonaManager as MainPersona, type OnWarning, type SdkWarning, type WalletOptions } from '${pkg.name}';
import { VericertsError as CommonError, fetchWellKnownJson, type WellKnownJsonFailure } from '${pkg.name}/common';
import { KeyManager as DomainKey, type Storage } from '${pkg.name}/keymanager';
import { PersonaManager as DomainPersona, type PersonaStorage } from '${pkg.name}/persona';
import { createDidResolver, type DidResolverLike } from '${pkg.name}/identity';
import { createDcqlWorkBudget, type DcqlWorkBudget, type CreatePresentationOptions } from '${pkg.name}/oid4vp';
import { decodeCompactJws, parseReceivedCredential, verifyReceivedSdJwtCredential, type ParsedReceivedCredential, type VerifiedReceivedSdJwtCredential, type DecodedJws, type JwtVcBody } from '${pkg.name}/credential';
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Assert<T extends true> = T;
type Contracts = [
  Assert<Equal<WellKnownJsonFailure, Parameters<typeof fetchWellKnownJson>[3]>>,
  Assert<Equal<Storage | undefined, NonNullable<ConstructorParameters<typeof DomainKey>[0]>['storage']>>,
  Assert<Equal<PersonaStorage, ConstructorParameters<typeof DomainPersona>[1]>>,
  Assert<ReturnType<typeof createDidResolver> extends DidResolverLike ? true : false>,
  Assert<Equal<DcqlWorkBudget, ReturnType<typeof createDcqlWorkBudget>>>,
  Assert<Equal<DecodedJws, ReturnType<typeof decodeCompactJws>>>,
  Assert<Equal<OnWarning | undefined, WalletOptions['onWarning']>>,
  Assert<Equal<SdkWarning, Parameters<OnWarning>[0]>>,
  Assert<Equal<ParsedReceivedCredential, ReturnType<typeof parseReceivedCredential>>>,
  Assert<Equal<VerifiedReceivedSdJwtCredential, Awaited<ReturnType<typeof verifyReceivedSdJwtCredential>>>>,
  Assert<Equal<'unverified', ParsedReceivedCredential['verification']>>,
  Assert<Equal<'verified', VerifiedReceivedSdJwtCredential['verification']>>,
];
const shared: typeof MainError = CommonError;
const keyClass: typeof MainKey = DomainKey;
const personaClass: typeof MainPersona = DomainPersona;
const budget: DcqlWorkBudget = createDcqlWorkBudget();
const presentationOptions: CreatePresentationOptions = {};
type CredentialBody = JwtVcBody;
void [shared, keyClass, personaClass, budget, presentationOptions];
export type { Contracts };
export type { CredentialBody };
` +
    didResourcesTypeFixture(pkg.name);
  for (const extension of ['mts', 'cts'])
    writeFileSync(join(consumer, `consumer.${extension}`), source);
  for (const [extension, module, moduleResolution] of [
    ['mts', 'Node16', 'Node16'],
    ['mts', 'NodeNext', 'NodeNext'],
    ['mts', 'ESNext', 'Bundler'],
    ['cts', 'Node16', 'Node16'],
    ['cts', 'NodeNext', 'NodeNext'],
  ]) {
    const config = {
      compilerOptions: {
        target: 'ES2022',
        lib: ['ES2022', 'DOM', 'DOM.Iterable'],
        strict: true,
        skipLibCheck: false,
        types: [],
        noEmit: true,
        module,
        moduleResolution,
      },
      files: [`consumer.${extension}`],
    };
    writeFileSync(join(consumer, 'tsconfig.json'), JSON.stringify(config));
    run(process.execPath, [
      fileURLToPath(new URL('./typescript-check.mjs', import.meta.url)),
      join(consumer, 'tsconfig.json'),
    ]);
  }
  console.log(
    `packed consumer: ${specifiers.length} entries x 5 strict type modes; OTel peers ${withOtel ? 'installed' : 'absent'}`,
  );
}
