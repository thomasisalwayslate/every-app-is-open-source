// Benchmark interface boundary, not an operating-system sandbox.
import {lstatSync, realpathSync} from 'node:fs';
import path from 'node:path';

function check(value, schema, location) {
  if (!schema || schema.$ref) throw new Error(`${location}: unsupported schema`);
  for (const keyword of ['anyOf', 'oneOf']) {
    if (schema[keyword]) {
      const matches = schema[keyword].filter(option => {
        try { check(value, {...schema, [keyword]: undefined, ...option}, location); return true; }
        catch { return false; }
      });
      if (!matches.length || keyword === 'oneOf' && matches.length !== 1)
        throw new Error(`${location}: no unambiguous allowed argument shape`);
      return;
    }
  }
  if (schema.allOf) {
    for (const option of schema.allOf) check(value, option, location);
    return;
  }
  if ('const' in schema && value !== schema.const || schema.enum && !schema.enum.includes(value))
    throw new Error(`${location}: value is outside the allowed set`);
  const kind = schema.type;
  const valid = {object: value !== null && typeof value === 'object' && !Array.isArray(value),
    array: Array.isArray(value), string: typeof value === 'string', boolean: typeof value === 'boolean',
    integer: Number.isSafeInteger(value), number: typeof value === 'number' && Number.isFinite(value),
    null: value === null};
  if (kind && !valid[kind]) throw new Error(`${location}: expected ${kind}`);
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const properties = schema.properties ?? {};
    for (const key of Object.keys(value)) {
      // Deliberately closed even if a provider permits arbitrary extra keys.
      if (!Object.hasOwn(properties, key)) throw new Error(`${location}: unknown argument ${key}`);
      check(value[key], properties[key], `${location}.${key}`);
    }
    for (const key of schema.required ?? [])
      if (!Object.hasOwn(value, key)) throw new Error(`${location}: missing ${key}`);
  } else if (Array.isArray(value)) {
    if (!schema.items && value.length) throw new Error(`${location}: undeclared array items`);
    if (value.length < (schema.minItems ?? 0) || value.length > (schema.maxItems ?? Infinity))
      throw new Error(`${location}: array length outside bounds`);
    value.forEach((item, index) => check(item, schema.items, `${location}[${index}]`));
  } else if (typeof value === 'string') {
    if (!kind && !schema.enum && !Object.hasOwn(schema, 'const'))
      throw new Error(`${location}: undeclared string argument`);
    if (value.length < (schema.minLength ?? 0) || value.length > (schema.maxLength ?? Infinity) ||
        schema.pattern && !new RegExp(schema.pattern).test(value))
      throw new Error(`${location}: string outside bounds`);
  } else if (typeof value === 'number') {
    if (value < (schema.minimum ?? -Infinity) || value > (schema.maximum ?? Infinity) ||
        typeof schema.exclusiveMinimum === 'number' && value <= schema.exclusiveMinimum ||
        typeof schema.exclusiveMaximum === 'number' && value >= schema.exclusiveMaximum)
      throw new Error(`${location}: number outside bounds`);
  }
}

export function validateArguments(catalog, name, args) {
  const tool = catalog.find(item => item.name === name);
  if (!tool) throw new Error('Unknown tool');
  if (args === null || typeof args !== 'object' || Array.isArray(args))
    throw new Error('Arguments must be an object');
  check(args, tool.inputSchema, name);
}

// Resolve existing ancestors too: new export paths must not escape via symlinks.
export function canonicalPath(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0'))
    throw new Error('An absolute local path is required');
  let existing = path.resolve(value);
  const tail = [];
  const present = candidate => {
    try { lstatSync(candidate); return true; }
    catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  };
  while (!present(existing)) {
    const parent = path.dirname(existing);
    if (parent === existing) throw new Error('No existing path ancestor');
    tail.unshift(path.basename(existing));
    existing = parent;
  }
  return path.join(realpathSync(existing), ...tail);
}

const PATH_ARGUMENTS = {
  open_binary: {path: 'target', snapshot_path: 'export'},
  close_binary: {snapshot_path: 'export'},
  export_evidence_bundle: {path: 'export'},
  binary_session: {expected_server_path: 'server'},
};

export function validatePaths(name, args, {target, runDir, serverPath}) {
  const policies = PATH_ARGUMENTS[name] ?? {};
  const selected = realpathSync(target);
  const exports = path.join(realpathSync(runDir), 'exports');
  const inspect = (value, key, location) => {
    if (value !== null && typeof value === 'object') {
      for (const [childKey, child] of Object.entries(value)) inspect(child, childKey, `${location}.${childKey}`);
      return;
    }
    if (typeof value !== 'string') return;
    const policy = policies[location];
    // An unreviewed path-bearing argument fails closed, regardless of schema.
    if (!policy && (/path$|directory$|(^|_)(file|filename|file_name|destination)$/i.test(key)))
      throw new Error(`Unreviewed path argument ${location}`);
    if (!policy) return; // e.g. search text and procedure symbols are literal data.
    const candidate = canonicalPath(value);
    const allowed = policy === 'target' ? candidate === selected :
      policy === 'server' ? serverPath && candidate === realpathSync(serverPath) :
      canonicalPath(exports) === exports && candidate.startsWith(exports + path.sep);
    if (!allowed) throw new Error('Only the selected target and run-local evidence exports are accessible');
  };
  for (const [key, value] of Object.entries(args)) inspect(value, key, key);
}

export function workflowPath(skill, relative) {
  if (typeof relative !== 'string' || path.isAbsolute(relative) ||
      !/^(SKILL\.md|references\/[A-Za-z0-9_-]+\.md)$/.test(relative))
    throw new Error('Only installed SKILL.md or references/<name>.md are available');
  const file = realpathSync(path.join(skill, relative));
  if (!file.startsWith(realpathSync(skill) + path.sep) || !file.endsWith('.md'))
    throw new Error('Only installed workflow Markdown is available');
  return file;
}
