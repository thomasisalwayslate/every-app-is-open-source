import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {canonicalPath, validateArguments, validatePaths, workflowPath} from '../benchmark/scope.mjs';

const catalog = [{name: 'inspect', inputSchema: {type: 'object', properties: {
  addresses: {type: 'array', items: {type: 'string'}, minItems: 1},
  filters: {type: 'object', properties: {offset: {type: 'integer', minimum: 0}}},
  view: {oneOf: [
    {type: 'object', properties: {kind: {const: 'native'}, limit: {type: 'integer'}}, required: ['kind']},
    {type: 'object', properties: {kind: {const: 'other'}, query: {type: 'string'}}, required: ['kind']},
  ]},
}, required: ['addresses']}}];

test('reject undeclared arguments regardless of their name, value or nesting', () => {
  for (const extra of [{secret_file: '/oracle'}, {source: '/oracle'}, {source: 1}, {path: '/oracle'}])
    assert.throws(() => validateArguments(catalog, 'inspect', {addresses: ['1000'], ...extra}), /unknown argument/);
  assert.throws(() => validateArguments(catalog, 'inspect', {addresses: ['1000'], filters: {source: '/oracle'}}));
  assert.throws(() => validateArguments(catalog, 'inspect', {addresses: [{file: '/oracle'}]}));
  assert.throws(() => validateArguments(catalog, 'inspect', {addresses: ['1000'], view: {kind: 'native', query: '/oracle'}}));
  assert.throws(() => validateArguments(catalog, 'missing', {}), /Unknown tool/);
  assert.throws(() => validateArguments(catalog, 'inspect', []), /object/);
});

test('preserve declared arguments and enforce types, bounds and union branches', () => {
  validateArguments(catalog, 'inspect', {addresses: ['1000'], filters: {offset: 0}, view: {kind: 'native', limit: 10}});
  validateArguments(catalog, 'inspect', {addresses: ['1000'], view: {kind: 'other', query: '/a literal search'}});
  for (const args of [{}, {addresses: []}, {addresses: ['1000'], filters: {offset: true}},
    {addresses: ['1000'], filters: {offset: -1}}]) assert.throws(() => validateArguments(catalog, 'inspect', args));
});

test('canonical target and export paths reject traversal and existing or dangling symlinks', t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'eaos-boundary-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const runDir = path.join(dir, 'run'), target = path.join(dir, 'program'), outside = path.join(dir, 'outside');
  mkdirSync(runDir); mkdirSync(outside); mkdirSync(path.join(runDir, 'exports'));
  writeFileSync(target, 'selected'); writeFileSync(path.join(outside, 'oracle'), 'secret');
  const scope = {target, runDir};
  validatePaths('open_binary', {path: target}, scope);
  symlinkSync(target, path.join(dir, 'alias'));
  validatePaths('open_binary', {path: path.join(dir, 'alias')}, scope);
  validatePaths('export_evidence_bundle', {path: path.join(runDir, 'exports/new/result.json')}, scope);
  assert.throws(() => validatePaths('open_binary', {path: path.join(outside, 'oracle')}, scope));
  assert.throws(() => validatePaths('open_binary', {path: path.join(runDir, 'exports/new.json')}, scope));
  assert.throws(() => validatePaths('export_evidence_bundle', {path: target}, scope));
  assert.throws(() => validatePaths('export_evidence_bundle', {path: path.join(runDir, 'exports/../../outside/oracle')}, scope));
  symlinkSync(outside, path.join(runDir, 'exports/escape'));
  assert.throws(() => validatePaths('export_evidence_bundle', {path: path.join(runDir, 'exports/escape/new.json')}, scope));
  symlinkSync(path.join(outside, 'not-created'), path.join(runDir, 'exports/dangling'));
  assert.throws(() => validatePaths('export_evidence_bundle', {path: path.join(runDir, 'exports/dangling')}, scope));
  assert.throws(() => validatePaths('new_tool', {other_path: target}, scope), /Unreviewed/);
  for (const value of ['relative', 'file:///tmp/program', target + '\0']) assert.throws(() => canonicalPath(value));
});

test('reject an export root that redirects outside the run directory', t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'eaos-export-root-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const runDir = path.join(dir, 'run'), target = path.join(dir, 'program');
  mkdirSync(runDir); mkdirSync(path.join(dir, 'outside')); writeFileSync(target, 'selected');
  symlinkSync(path.join(dir, 'outside'), path.join(runDir, 'exports'));
  assert.throws(() => validatePaths('export_evidence_bundle', {path: path.join(runDir, 'exports/result')}, {target, runDir}));
});

test('workflow reads accept installed documents and reject traversal, arbitrary files and symlink escapes', t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'eaos-skill-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const skill = path.join(dir, 'skill'); mkdirSync(skill); mkdirSync(path.join(skill, 'references'));
  writeFileSync(path.join(skill, 'SKILL.md'), 'workflow'); writeFileSync(path.join(skill, 'references/native.md'), 'native');
  writeFileSync(path.join(dir, 'oracle.md'), 'secret');
  symlinkSync(path.join(dir, 'oracle.md'), path.join(skill, 'references/escape.md'));
  writeFileSync(path.join(skill, 'source.js'), 'not a workflow');
  symlinkSync(path.join(skill, 'source.js'), path.join(skill, 'references/internal.md'));
  assert.equal(workflowPath(skill, 'SKILL.md'), canonicalPath(path.join(skill, 'SKILL.md')));
  workflowPath(skill, 'references/native.md');
  for (const input of ['../oracle.md', path.join(dir, 'oracle.md'), 'references/escape.md', 'references/internal.md', 'references/../SKILL.md'])
    assert.throws(() => workflowPath(skill, input));
});
