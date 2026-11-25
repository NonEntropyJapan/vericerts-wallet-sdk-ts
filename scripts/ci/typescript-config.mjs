import { lstatSync, readdirSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { ts } from '../lib/load-typescript.mjs';

const system = {
  ...ts.sys,
  realpath: realpathSync,
  entries: (dir) => readdirSync(dir),
  isLink: (file) => lstatSync(file, { throwIfNoEntry: false })?.isSymbolicLink() ?? false,
  // Directory entries are checked before handing a search to TS's glob matcher.
  search: (...args) => ts.sys.readDirectory(...args),
};

function inside(root, target) {
  const relative = path.relative(root, target);
  return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function pathBoundary(root, io) {
  function absolute(directory, value) {
    if (
      typeof value !== 'string' ||
      !value ||
      value.includes('\0') ||
      (/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(value) && !path.isAbsolute(value))
    )
      throw new Error('invalid SDK TypeScript config path');
    const target = path.resolve(directory, value.replaceAll('\\', '/'));
    if (!inside(root, target)) throw new Error('config path escapes SDK');
    return target;
  }

  function checked(target) {
    const file = absolute(root, target);
    // A missing leaf is fine during resolution, but its closest existing ancestor
    // must still be checked (for example, an absent file under a linked directory).
    let current = file;
    while (true) {
      try {
        const actual = io.realpath(current);
        if (!inside(root, actual)) throw new Error('TypeScript path symlink escapes SDK');
        return path.join(actual, path.relative(current, file));
      } catch (error) {
        if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
        if (io.isLink?.(current)) throw new Error('Unresolved SDK TypeScript symlink');
        if (current === root) throw error;
        current = path.dirname(current);
      }
    }
  }

  return { absolute, checked };
}

const pathOptions = [
  'baseUrl',
  'rootDir',
  'outDir',
  'declarationDir',
  'outFile',
  'tsBuildInfoFile',
];

const fileReference = /^(?:\.{1,2}[/\\]|[/\\]|[a-z]:[/\\]|file:)/i;
const typePackage = /^(?:@[a-z0-9_.-]+\/)?[a-z0-9_][a-z0-9_.-]*$/i;

function verifyPackageEntries(name, text, { absolute, checked }) {
  const parsed = ts.parseConfigFileTextToJson(name, text);
  if (parsed.error) failDiagnostic(parsed.error);
  const pkg = parsed.config ?? {};
  const verify = (value) => {
    if (typeof value === 'string' && value)
      checked(absolute(path.dirname(name), value).split(/[?*]/, 1)[0]);
  };
  for (const field of ['types', 'typings', 'main']) verify(pkg[field]);
  for (const paths of Object.values(pkg.typesVersions ?? {}))
    for (const targets of Object.values(paths ?? {}))
      if (Array.isArray(targets)) targets.forEach(verify);
}

function verifyConfigPaths(config, dir, { absolute, checked }) {
  const check = (value, base = dir) => {
    if (typeof value !== 'string') throw new Error('invalid SDK TypeScript config path');
    const substituted = value.replace(/^\$\{configDir\}(?=[/\\]|$)/, dir);
    const target = absolute(base, substituted);
    checked(target.split(/[?*]/, 1)[0]);
    return target;
  };
  const checkOptions = (options) => {
    for (const key of pathOptions) if (options[key] !== undefined) check(options[key]);
    for (const key of ['typeRoots', 'rootDirs'])
      if (Array.isArray(options[key])) for (const value of options[key]) check(value);
    const base = options.baseUrl === undefined ? dir : check(options.baseUrl);
    for (const values of Object.values(options.paths ?? {}))
      if (Array.isArray(values)) for (const value of values) check(value, base);
  };
  const options = config.compilerOptions ?? {};
  checkOptions(options);
  if (Array.isArray(options.types))
    for (const value of options.types) {
      if (typeof value === 'string' && fileReference.test(value)) check(value);
      else if (typeof value !== 'string' || !typePackage.test(value))
        throw new Error('invalid SDK TypeScript type reference');
    }
  for (const key of ['files', 'include', 'exclude'])
    if (Array.isArray(config[key])) for (const value of config[key]) check(value);
  for (const reference of Array.isArray(config.references) ? config.references : [])
    check(reference?.path);
  const extensions = Array.isArray(config.extends)
    ? config.extends
    : config.extends === undefined
      ? []
      : [config.extends];
  for (const extension of extensions) {
    if (
      typeof extension !== 'string' ||
      (!extension.startsWith('./') && !extension.startsWith('../') && !path.isAbsolute(extension))
    )
      throw new Error('TypeScript extends must be an explicit SDK file');
    check(extension);
  }
}

function createHosts(root, io, boundary) {
  const { absolute, checked } = boundary;
  const visitedDirectories = new Set();
  // TS uses parent-directory probes for package/type lookup. Missing or out-of-root
  // candidates are not searched. Explicit paths and actual content reads are strict.
  const probe = (name, exists) => inside(root, path.resolve(root, name)) && exists(checked(name));
  const fs = {
    getCurrentDirectory: () => root,
    directoryExists: (name) => probe(name, io.directoryExists),
    fileExists: (name) => probe(name, io.fileExists),
    readFile(name) {
      const text = io.readFile(checked(name));
      if (text !== undefined && path.basename(name) === 'package.json')
        verifyPackageEntries(absolute(root, name), text, boundary);
      return text;
    },
    realpath: checked,
    getDirectories(name) {
      if (!fs.directoryExists(name)) return [];
      const dir = checked(name);
      return io.entries(dir).filter((entry) => fs.directoryExists(path.join(dir, entry)));
    },
  };

  function verifyTree(dir) {
    const actual = checked(dir);
    if (visitedDirectories.has(actual) || !fs.directoryExists(actual)) return;
    visitedDirectories.add(actual);
    for (const entry of io.entries(actual)) {
      const child = checked(path.join(actual, entry));
      if (fs.directoryExists(child)) verifyTree(child);
    }
  }

  const configHost = {
    ...fs,
    useCaseSensitiveFileNames: io.useCaseSensitiveFileNames,
    onUnRecoverableConfigFileDiagnostic: failDiagnostic,
    readFile(name) {
      const value = fs.readFile(name);
      if (value === undefined) return value;
      const parsed = ts.parseConfigFileTextToJson(name, value);
      if (parsed.error) failDiagnostic(parsed.error);
      verifyConfigPaths(parsed.config, path.dirname(absolute(root, name)), boundary);
      return value;
    },
    readDirectory(directory, extensions, excludes, includes, depth) {
      const dir = absolute(root, directory);
      // Includes can be rebased by inheritance to a sibling SDK directory.
      for (const pattern of includes ?? []) {
        const target = absolute(dir, pattern);
        const firstWildcard = target.search(/[?*]/);
        if (firstWildcard < 0) verifyTree(target);
        else verifyTree(path.dirname(target.slice(0, firstWildcard)));
      }
      verifyTree(dir);
      const matches = io.search(dir, extensions, excludes, includes, depth);
      for (const match of matches) checked(match);
      return matches;
    },
  };
  return { fs, configHost };
}

function failDiagnostic(diagnostic) {
  throw new Error(ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'));
}

function verifySourceReferences(name, text, boundary) {
  const { importedFiles, referencedFiles, typeReferenceDirectives } = ts.preProcessFile(
    text,
    true,
    true,
  );
  const dir = path.dirname(name);
  for (const { fileName } of referencedFiles) boundary.checked(boundary.absolute(dir, fileName));
  for (const { fileName } of [...importedFiles, ...typeReferenceDirectives])
    if (fileReference.test(fileName)) boundary.checked(boundary.absolute(dir, fileName));
}

export function checkTypeScriptConfigs(directory, configs, io = system) {
  if (!configs.length) return [];
  const root = io.realpath(path.resolve(directory));
  const boundary = pathBoundary(root, io);
  const { absolute, checked } = boundary;
  const { fs, configHost } = createHosts(root, io, boundary);
  const parsed = new Map();
  const verified = new Set();
  const visiting = new Set();

  function parse(file) {
    const name = absolute(root, file);
    checked(name);
    if (!parsed.has(name)) {
      const config = ts.getParsedCommandLineOfConfigFile(name, {}, configHost);
      if (!config) throw new Error('Invalid SDK TypeScript config');
      if (config.errors.length) failDiagnostic(config.errors[0]);
      for (const input of config.fileNames) checked(input);
      if (config.options.baseUrl)
        for (const value of Object.values(config.options.paths ?? {}).flat())
          checked(absolute(config.options.baseUrl, value).split(/[?*]/, 1)[0]);
      for (const key of pathOptions) if (config.options[key]) checked(config.options[key]);
      for (const key of ['typeRoots', 'rootDirs'])
        for (const value of config.options[key] ?? []) checked(value);
      parsed.set(name, config);
    }
    return parsed.get(name);
  }

  function verify(file) {
    const name = absolute(root, file);
    const actualConfig = checked(name);
    if (visiting.has(actualConfig)) throw new Error('Cyclic SDK TypeScript project references');
    if (verified.has(name)) return;
    visiting.add(actualConfig);
    const config = parse(name);
    for (const reference of config.projectReferences ?? [])
      verify(ts.resolveProjectReferencePath(reference));
    if (!config.fileNames.length && !config.projectReferences?.length)
      throw new Error('No SDK TypeScript inputs');
    if (config.fileNames.length) {
      const compiler = ts.createCompilerHost(config.options);
      const lib = checked(path.join(root, 'node_modules/typescript/lib'));
      Object.assign(compiler, fs, {
        getDefaultLibLocation: () => lib,
        getDefaultLibFileName: (options) => path.join(lib, ts.getDefaultLibFileName(options)),
        getParsedCommandLine: parse,
        useCaseSensitiveFileNames: () => io.useCaseSensitiveFileNames,
        writeFile() {
          throw new Error('SDK TypeScript boundary must not emit files');
        },
        getSourceFile(input, languageVersion) {
          const target = checked(input);
          const text = io.readFile(target);
          if (text === undefined) return undefined;
          verifySourceReferences(absolute(root, input), text, boundary);
          return ts.createSourceFile(input, text, languageVersion, true);
        },
      });
      const program = ts.createProgram({
        rootNames: config.fileNames,
        options: config.options,
        projectReferences: config.projectReferences,
        host: compiler,
      });
      const [optionsError] = program.getOptionsDiagnostics();
      if (optionsError) failDiagnostic(optionsError);
      const actual = new Set(program.getSourceFiles().map((source) => checked(source.fileName)));
      if (!actual.size || config.fileNames.some((input) => !actual.has(checked(input))))
        throw new Error('SDK TypeScript program omitted configured inputs');
    }
    visiting.delete(actualConfig);
    verified.add(name);
  }

  const problems = [];
  for (const config of configs) {
    try {
      verify(absolute(root, config));
    } catch (error) {
      visiting.clear();
      problems.push(`${config}: ${error.message}`);
    }
  }
  return problems;
}
