// Run: node tests/handoff.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const cpp = readFileSync(new URL('../src/ESPAsyncWiFiManager.cpp', import.meta.url), 'utf8');
const fragment = cpp.split('// JavaScript Logic')[1].split('page += FPSTR(HTTP_END)')[0];
const script = fragment.split('\n').map(line => {
  const literal = line.match(/page \+= F\((".*")\);/);
  if (literal) return JSON.parse(literal[1]);
  if (line.includes('page += redirectUrl;')) return 'https://lukerobotarm.com/#control';
  if (line.includes('page += String(')) return '30';
  return '';
}).join('').replace(/^<script>|<\/script>$/g, '');

function portal(result, wan = false) {
  const intervals = new Map();
  const elements = new Map();
  const calls = [];
  const location = { href: '', replace(url) { this.href = url; } };
  runInNewContext(script, {
    document: { getElementById(id) {
      if (!elements.has(id)) elements.set(id, { style: {} });
      return elements.get(id);
    } },
    window: { location },
    setInterval(fn) { const id = intervals.size + 1; intervals.set(id, fn); return id; },
    clearInterval(id) { intervals.delete(id); },
    fetch(url) {
      calls.push(url);
      return url === '/status' ? Promise.resolve({ text: () => Promise.resolve(result) })
        : wan ? Promise.resolve({}) : Promise.reject(new Error('offline'));
    },
  });
  return { intervals, elements, calls, location };
}
const settle = () => new Promise(resolve => setImmediate(resolve));
let p = portal('CONNECTING', true);
p.intervals.get(2)();
assert.deepEqual(p.calls, [], 'Cellular internet must not count as robot success');
for (let i = 0; i < 30; i++) p.intervals.get(3)();
assert.equal(p.location.href, '', 'Unconfirmed connection must not redirect');
assert.equal(p.elements.get('fallback').style.display, 'block');
p = portal('FAILED', true);
p.intervals.get(1)(); await settle();
assert.equal(p.intervals.size, 0);
assert.equal(p.location.href, '');
assert.equal(p.elements.get('controller-section').style.display, 'none');
p = portal('SUCCESS');
p.intervals.get(1)(); await settle();
for (let i = 0; i < 15; i++) p.intervals.get(3)();
assert.equal(p.location.href, 'https://lukerobotarm.com/#control');
p = portal('SUCCESS', true);
p.intervals.get(1)(); await settle();
p.intervals.get(2)(); await settle();
assert.equal(p.location.href, 'https://lukerobotarm.com/#control');

console.log('Portal connection checks passed.');
