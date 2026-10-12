import assert from 'node:assert/strict';
import { test } from 'node:test';
import { baseDomain, hostFromUrl, siteMatches } from '../extension/site-match.js';

test('baseDomain keeps the registrable part of a hostname', () => {
  assert.equal(baseDomain('beta.vezly.ai'), 'vezly.ai');
  assert.equal(baseDomain('vezly.ai'), 'vezly.ai');
  assert.equal(baseDomain('a.b.c.example.com'), 'example.com');
});

test('baseDomain handles two-part public suffixes like co.uk and co.in', () => {
  assert.equal(baseDomain('app.example.co.uk'), 'example.co.uk');
  assert.equal(baseDomain('login.example.co.in'), 'example.co.in');
  assert.equal(baseDomain('portal.example.com.au'), 'example.com.au');
});

test('baseDomain leaves localhost and IP addresses whole', () => {
  assert.equal(baseDomain('localhost'), 'localhost');
  assert.equal(baseDomain('172.24.3.43'), '172.24.3.43');
});

test('a saved domain matches the same site and its sibling subdomains', () => {
  assert.equal(siteMatches('beta.vezly.ai', 'beta.vezly.ai'), true);
  assert.equal(siteMatches('app.vezly.ai', 'auth.vezly.ai'), true);
  assert.equal(siteMatches('vezly.ai', 'beta.vezly.ai'), true);
  assert.equal(siteMatches('www.vezly.ai', 'vezly.ai'), true);
});

test('look-alike and unrelated domains never match', () => {
  assert.equal(siteMatches('vezly.ai', 'vezly.ai.evil.com'), false);
  assert.equal(siteMatches('vezly.ai', 'evilvezly.ai'), false);
  assert.equal(siteMatches('vezly.ai', 'chatomate.com'), false);
  assert.equal(siteMatches('example.co.uk', 'other.co.uk'), false);
});

test('missing domains never match, so old accounts sort as before', () => {
  assert.equal(siteMatches('', 'vezly.ai'), false);
  assert.equal(siteMatches(undefined, 'vezly.ai'), false);
  assert.equal(siteMatches('vezly.ai', ''), false);
});

test('matching ignores case', () => {
  assert.equal(siteMatches('Beta.Vezly.AI', 'beta.vezly.ai'), true);
});

test('hostFromUrl reads http(s) pages only', () => {
  assert.equal(hostFromUrl('https://Beta.Vezly.ai:8443/login?x=1'), 'beta.vezly.ai');
  assert.equal(hostFromUrl('http://localhost:3000/'), 'localhost');
  assert.equal(hostFromUrl('chrome://extensions'), '');
  assert.equal(hostFromUrl('file:///tmp/a.html'), '');
  assert.equal(hostFromUrl('not a url'), '');
  assert.equal(hostFromUrl(undefined), '');
});
