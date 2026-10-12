import assert from 'node:assert/strict';
import { test } from 'node:test';
import { assertAllowedDbUrl, describeDbUrl, loadAllowedHosts, maskDbUrl } from '../host/db-url.mjs';

const ALLOWED = ['localhost', '127.0.0.1', '172.24.3.43'];

test('accepts allowed hosts that name a database', () => {
  for (const url of [
    'mongodb://localhost:27017/vezly',
    'mongodb://127.0.0.1:27018/chatomate',
    'mongodb://localhost/vezly',
    'mongodb://user:pass@172.24.3.43:27017/hiren-chatomate-platform?authSource=admin',
  ]) {
    assert.doesNotThrow(() => assertAllowedDbUrl(url, ALLOWED), url);
  }
});

test('rejects hosts that are not on the allow-list', () => {
  for (const url of ['mongodb://10.0.0.5:27017/vezly', 'mongodb://localhost.evil.com:27017/vezly']) {
    assert.throws(() => assertAllowedDbUrl(url, ALLOWED), /is not allowed/, url);
  }
});

test('rejects malformed URLs, other schemes and missing database names', () => {
  for (const url of [
    'mongodb+srv://cluster.mongodb.net/vezly',
    'mongodb://localhost:27017/',
    'mongodb://localhost:27017',
    'not a url',
    '',
    undefined,
  ]) {
    assert.throws(() => assertAllowedDbUrl(url, ALLOWED), /Not a valid MongoDB URL/, String(url));
  }
});

test('error messages never contain the password', () => {
  const url = 'mongodb://hiren:s3cret-pass@10.0.0.5:27017/';
  assert.throws(
    () => assertAllowedDbUrl(url, ALLOWED),
    (err) => !err.message.includes('s3cret-pass'),
  );
});

test('maskDbUrl hides only the password', () => {
  assert.equal(
    maskDbUrl('mongodb://hiren:s3cret@172.24.3.43:27017/db?authSource=admin'),
    'mongodb://hiren:***@172.24.3.43:27017/db?authSource=admin',
  );
  assert.equal(maskDbUrl('mongodb://localhost:27017/vezly'), 'mongodb://localhost:27017/vezly');
});

test('always allows this machine, plus the hosts in allowed-hosts.json', () => {
  const hosts = loadAllowedHosts();
  assert.ok(hosts.includes('localhost'));
  assert.ok(hosts.includes('127.0.0.1'));
  assert.ok(hosts.includes('172.24.3.43'));
});

test('describeDbUrl gives host and database only, never the credentials', () => {
  const label = describeDbUrl('mongodb://admin:s3cret-pass@172.24.3.43:27017/hiren-chatomate?authSource=admin');
  assert.deepEqual(label, { host: '172.24.3.43:27017', database: 'hiren-chatomate' });
  assert.ok(!JSON.stringify(label).includes('s3cret-pass'));
  assert.ok(!JSON.stringify(label).includes('admin:'));
});
