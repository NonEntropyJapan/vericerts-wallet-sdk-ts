export const SOURCE_EXTENSIONS = ['ts', 'tsx', 'mts', 'cts', 'js', 'jsx', 'mjs', 'cjs'];
export const SOURCE_EXTENSION_RE = new RegExp(`\\.(?:${SOURCE_EXTENSIONS.join('|')})$`);
