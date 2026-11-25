import assert from 'node:assert/strict';
import { existsSync, realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { containedFile, inside, ownTypeScript } from './containment.mjs';

export function checkTypeConfig(consumer, configPath) {
  const root = realpathSync(consumer);
  const ts = ownTypeScript(root);
  const allowed = (path) =>
    inside(root, resolve(path)) && existsSync(path) && inside(root, realpathSync(path));
  const readFile = (path) => {
    containedFile(root, path);
    return ts.sys.readFile(path);
  };
  const host = {
    ...ts.sys,
    fileExists: (path) => allowed(path) && ts.sys.fileExists(path),
    directoryExists: (path) => allowed(path) && ts.sys.directoryExists(path),
    readFile,
    realpath: (path) => containedFile(root, path),
  };
  const config = ts.readConfigFile(containedFile(root, configPath), readFile);
  assert.equal(config.error, undefined, 'Cannot read consumer type configuration');
  const parsed = ts.parseJsonConfigFileContent(config.config, host, root);
  assert.equal(parsed.errors.length, 0, 'Invalid consumer type configuration');
  assert.ok(parsed.fileNames.length > 0, 'Empty consumer type check');
  const compiler = ts.createCompilerHost(parsed.options);
  const getSourceFile = compiler.getSourceFile.bind(compiler);
  Object.assign(compiler, host, {
    getCurrentDirectory: () => root,
    useCaseSensitiveFileNames: () => ts.sys.useCaseSensitiveFileNames,
    getSourceFile(path, ...args) {
      containedFile(root, path);
      return getSourceFile(path, ...args);
    },
  });
  const program = ts.createProgram(parsed.fileNames, parsed.options, compiler);
  const files = program.getSourceFiles().map((file) => containedFile(root, file.fileName));
  assert.ok(files.length > 0, 'No declarations were loaded');
  const errors = ts.getPreEmitDiagnostics(program);
  assert.equal(errors.length, 0, 'Consumer declaration compilation failed');
  return files;
}

if (
  process.argv[1] &&
  existsSync(process.argv[1]) &&
  realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
) {
  try {
    const files = checkTypeConfig(process.cwd(), resolve(process.argv[2]));
    console.log(`consumer type closure: ${files.length} contained files`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
