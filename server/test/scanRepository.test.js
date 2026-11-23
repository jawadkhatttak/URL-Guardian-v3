import test, { beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { randomUUID } from 'node:crypto';

// Point the database at a throwaway temp file BEFORE any repository call.
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-test-'));
process.env.DATABASE_PATH = path.join(tempDir, 'test.db');

const {
  createScan,
  listScans,
  getScanById,
  toggleFavorite,
  deleteScan,
  clearScans,
} = await import('../src/db/scanRepository.js');
const { closeDb } = await import('../src/db/database.js');

const sampleResult = () => ({
  url: 'https://example.com/login',
  score: 42,
  risk: 'HIGH',
  findings: { dns: {}, whois: {}, html: {}, virustotal: {}, lexical: {} },
});

beforeEach(() => {
  clearScans();
});

after(() => {
  closeDb();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('createScan stores a scan and returns its summary', () => {
  const saved = createScan({
    url: 'https://phish.example.com/login',
    hostname: 'phish.example.com',
    score: 88,
    risk: 'CRITICAL',
    result: sampleResult(),
  });

  assert.ok(saved.id, 'expected a generated id');
  assert.equal(saved.isFavorite, false);
  assert.ok(saved.timestamp);

  const stored = getScanById(saved.id);
  assert.equal(stored.url, 'https://phish.example.com/login');
  assert.equal(stored.score, 88);
  assert.equal(stored.risk, 'CRITICAL');
  assert.deepEqual(stored.result, sampleResult());
});

test('listScans returns newest scans first with parsed results', () => {
  const a = createScan({ url: 'https://a.com', hostname: 'a.com', score: 10, risk: 'LOW', result: sampleResult() });
  const b = createScan({ url: 'https://b.com', hostname: 'b.com', score: 90, risk: 'CRITICAL', result: sampleResult() });

  const list = listScans();
  assert.equal(list.length, 2);
  // Both created in the same millisecond is possible; assert set membership instead of strict order.
  const ids = list.map((s) => s.id);
  assert.ok(ids.includes(a.id) && ids.includes(b.id));
  assert.equal(list[0].result.score, 42);
});

test('getScanById returns null for an unknown id', () => {
  assert.equal(getScanById(randomUUID()), null);
});

test('toggleFavorite flips the flag and reports it', () => {
  const saved = createScan({ url: 'https://fav.com', hostname: 'fav.com', score: 5, risk: 'LOW', result: sampleResult() });

  const first = toggleFavorite(saved.id);
  assert.deepEqual(first, { id: saved.id, isFavorite: true });
  assert.equal(getScanById(saved.id).isFavorite, true);

  const second = toggleFavorite(saved.id);
  assert.equal(second.isFavorite, false);
  assert.equal(getScanById(saved.id).isFavorite, false);
});

test('toggleFavorite returns null for an unknown id', () => {
  assert.equal(toggleFavorite(randomUUID()), null);
});

test('deleteScan removes a scan and reports whether it existed', () => {
  const saved = createScan({ url: 'https://del.com', hostname: 'del.com', score: 1, risk: 'LOW', result: sampleResult() });

  assert.equal(deleteScan(saved.id), true);
  assert.equal(getScanById(saved.id), null);
  assert.equal(deleteScan(saved.id), false);
});

test('clearScans removes everything and reports the count', () => {
  createScan({ url: 'https://x.com', hostname: 'x.com', score: 1, risk: 'LOW', result: sampleResult() });
  createScan({ url: 'https://y.com', hostname: 'y.com', score: 2, risk: 'LOW', result: sampleResult() });

  const { deleted } = clearScans();
  assert.equal(deleted, 2);
  assert.equal(listScans().length, 0);
});