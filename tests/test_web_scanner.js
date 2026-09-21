// Synthetic fixtures only. These tests establish behavior, not malware coverage.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

function scanner() {
  const nodes = new Map();
  const node = id => {
    if (!nodes.has(id)) nodes.set(id, { files: [], innerHTML: '', textContent: '', handlers: {},
      addEventListener(name, callback) { this.handlers[name] = callback; } });
    return nodes.get(id);
  };
  let initialize;
  let reads = 0;
  const readers = [];
  const context = vm.createContext({
    document: { getElementById: node },
    window: { addEventListener(name, callback) { initialize = callback; } },
    FileReader: class { constructor() { readers.push(this); } readAsText() { reads++; } },
  });
  const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
  vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], context);
  initialize();
  return { context, node, readers, reads: () => reads,
    analyze(text) { context.fixture = text; vm.runInContext('analyzeText(fixture, "fixture.txt", 0)', context); },
    state() { return JSON.parse(vm.runInContext('JSON.stringify(scanState)', context)); } };
}

test('input cannot exempt a patterns block and locations use original text', () => {
  const s = scanner();
  const token = 'sk-' + 'A'.repeat(48);
  s.analyze('patterns = [\n' + token + '\n];\n' + token);
  const finding = Object.values(s.state().highRisk)[0];
  assert.ok(finding);
  assert.deepEqual(finding.matches.map(x => x.line), [2, 4]);
});

test('all occurrences are counted while retained examples and secret display are bounded', () => {
  const s = scanner();
  const token = 'sk-' + 'B'.repeat(48);
  s.analyze(Array(9).fill(token).join('\n'));
  const finding = Object.values(s.state().highRisk)[0];
  assert.equal(finding.count, 9);
  assert.equal(finding.matches.length, 5);
  assert.ok(!s.node('result').innerHTML.includes(token));
  assert.match(s.node('result').innerHTML, /9 matches/);
});

test('dismissal uses its message and never claims the file is repaired or safe', () => {
  const s = scanner();
  s.analyze('sk-' + 'C'.repeat(48));
  const message = Object.keys(s.state().highRisk)[0];
  s.node('result').handlers.click({ target: { closest: () => ({
    dataset: { severity: 'highRisk', message: encodeURIComponent(message) },
  }) } });
  assert.equal(Object.keys(s.state().highRisk).length, 0);
  assert.match(s.node('summaryNote').textContent, /dismissed/i);
  assert.match(s.node('result').innerHTML, /not.*repair|not.*modified/i);
});

test('oversized and unsupported selections are rejected before reading', () => {
  const s = scanner();
  for (const file of [{ name: 'big.txt', size: 1048577 }, { name: 'sample.exe', size: 10 }]) {
    s.node('fileInput').files = [file];
    vm.runInContext('scan()', s.context);
  }
  assert.equal(s.reads(), 0);
});

test('empty results communicate limits and markup stays escaped', () => {
  const s = scanner();
  s.analyze('ordinary prose');
  assert.match(s.node('result').innerHTML, /not.*proof|does not.*safe/i);
  assert.equal(vm.runInContext('escapeHtml("<img onerror=alert(1)>")', s.context), '&lt;img onerror=alert(1)&gt;');
});

test('private-key headers match without requiring a word boundary before dashes', () => {
  const s = scanner();
  s.analyze('-----BEGIN PRIVATE KEY-----\n-----BEGIN RSA PRIVATE KEY-----\n-----BEGIN OPENSSH PRIVATE KEY-----');
  const finding = s.state().highRisk['Private-key header pattern matched.'];
  assert.equal(finding.count, 3);
  assert.deepEqual(finding.matches.map(x => x.line), [1, 2, 3]);
});

test('an older asynchronous read or error cannot replace a newer scan', () => {
  const s = scanner();
  for (const name of ['old.txt', 'new.txt']) {
    s.node('fileInput').files = [{ name, size: 20 }];
    vm.runInContext('scan()', s.context);
  }
  s.readers[1].onload({ target: { result: 'ordinary prose' } });
  const summary = s.node('summaryNote').textContent;
  s.readers[0].onload({ target: { result: 'sk-' + 'D'.repeat(48) } });
  s.readers[0].onerror();
  assert.equal(s.state().fileName, 'new.txt');
  assert.equal(s.node('summaryNote').textContent, summary);
  assert.equal(Object.keys(s.state().highRisk).length, 0);
});

test('invalid decoded content clears prior findings and does not report a clean scan', () => {
  const s = scanner();
  for (const invalid of [null, 'a\u0000b', 'x'.repeat(1048577)]) {
    s.analyze('sk-' + 'E'.repeat(48));
    s.analyze(invalid);
    assert.equal(s.node('result').innerHTML, '');
    assert.equal(s.node('summary').innerHTML, '');
    assert.match(s.node('summaryNote').textContent, /Not analyzed/);
  }
});
