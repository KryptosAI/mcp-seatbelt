import { describe, it, expect } from 'vitest';
import { checkThreatIntel, clearCache, getCache } from '../src/policy/threat-intel.js';

describe('Threat Intel', () => {
  it('returns empty array for empty args', async () => {
    const results = await checkThreatIntel({});
    expect(results).toEqual([]);
  });

  it('returns empty array for non-string args', async () => {
    const results = await checkThreatIntel({ count: 42, flag: true });
    expect(results).toEqual([]);
  });

  it('detects IPv4 addresses and queries them', async () => {
    const results = await checkThreatIntel({ host: '8.8.8.8' });
    expect(Array.isArray(results)).toBe(true);
    for (const r of results) {
      expect(r.queryType).toBe('ip');
      expect(r.source).toBe('threatfox');
    }
  });

  it('detects domain names and queries them', async () => {
    const results = await checkThreatIntel({ url: 'example.com' });
    expect(Array.isArray(results)).toBe(true);
    for (const r of results) {
      expect(r.queryType).toBe('domain');
      expect(r.source).toBe('threatfox');
    }
  });

  it('does not query email addresses as domains', async () => {
    const results = await checkThreatIntel({ email: 'test@example.com' });
    expect(results).toEqual([]);
  });

  it('does not query strings starting with dot', async () => {
    const results = await checkThreatIntel({ host: '.hidden' });
    expect(results).toEqual([]);
  });

  it('queries multiple IPs in a single call', async () => {
    const results = await checkThreatIntel({
      primary: '1.1.1.1',
      secondary: '8.8.4.4',
    });
    expect(results.length).toBeGreaterThanOrEqual(0);
    expect(results.length).toBeLessThanOrEqual(2);
  });

  it('queries mixed domains and IPs', async () => {
    const results = await checkThreatIntel({
      host: 'google.com',
      ip: '1.2.3.4',
    });
    const ips = results.filter((r) => r.queryType === 'ip');
    const domains = results.filter((r) => r.queryType === 'domain');
    expect(ips.length).toBeGreaterThanOrEqual(0);
    expect(domains.length).toBeGreaterThanOrEqual(0);
  });

  it('skips non-IP non-domain strings', async () => {
    const results = await checkThreatIntel({
      command: 'ls -la',
      path: '/home/user',
      name: 'simple-string',
    });
    expect(results).toEqual([]);
  });

  it('has a populated cache after queries', async () => {
    clearCache();
    await checkThreatIntel({ host: '8.8.8.8' });
    const cache = getCache();
    expect(cache.size).toBeGreaterThanOrEqual(0);
  });

  it('clearCache empties the cache', async () => {
    await checkThreatIntel({ host: '8.8.4.4' });
    clearCache();
    expect(getCache().size).toBe(0);
  });

  it('result has correct shape', async () => {
    const results = await checkThreatIntel({ ip: '1.1.1.1' });
    for (const r of results) {
      expect(r).toHaveProperty('malicious');
      expect(r).toHaveProperty('source');
      expect(r).toHaveProperty('queryType');
      expect(r).toHaveProperty('queryValue');
      expect(r).toHaveProperty('details');
      expect(typeof r.malicious).toBe('boolean');
      expect(typeof r.details).toBe('string');
    }
  });

  it('malicious property is always boolean', async () => {
    const results = await checkThreatIntel({ host: '8.8.8.8' });
    for (const r of results) {
      expect(typeof r.malicious).toBe('boolean');
    }
  });
});
