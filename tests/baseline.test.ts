import { describe, it, expect, beforeEach } from 'vitest';
import { BehavioralBaseline } from '../src/policy/engine.js';
import type { ToolProfile, Deviation } from '../src/policy/engine.js';

describe('BehavioralBaseline', () => {
  let baseline: BehavioralBaseline;

  beforeEach(() => {
    baseline = new BehavioralBaseline();
  });

  describe('observe', () => {
    it('creates a new profile on first observation', () => {
      baseline.observe('read_file', { filePath: '/tmp/test.txt' });
      expect(baseline.profiles.has('read_file')).toBe(true);

      const profile = baseline.profiles.get('read_file')!;
      expect(profile.toolName).toBe('read_file');
      expect(profile.totalCalls).toBe(1);
      expect(profile.firstSeen).toBeTruthy();
      expect(profile.lastSeen).toBeTruthy();
    });

    it('increments call count on repeated observations', () => {
      baseline.observe('read_file', { filePath: '/tmp/a.txt' });
      baseline.observe('read_file', { filePath: '/tmp/b.txt' });
      baseline.observe('read_file', { filePath: '/tmp/c.txt' });

      const profile = baseline.profiles.get('read_file')!;
      expect(profile.totalCalls).toBe(3);
    });

    it('tracks hour distribution', () => {
      baseline.observe('read_file', { filePath: '/tmp/test.txt' });
      const profile = baseline.profiles.get('read_file')!;
      const currentHour = new Date().getHours();
      expect(profile.hourDistribution[currentHour]).toBe(1);
    });

    it('tracks typical argument keys', () => {
      baseline.observe('read_file', { filePath: '/tmp/test.txt', encoding: 'utf-8' });
      const profile = baseline.profiles.get('read_file')!;
      expect(profile.typicalArgs.has('filePath')).toBe(true);
      expect(profile.typicalArgs.has('encoding')).toBe(true);
    });

    it('tracks argument key counts', () => {
      baseline.observe('read_file', { filePath: '/tmp/a.txt' });
      baseline.observe('read_file', { filePath: '/tmp/b.txt' });
      baseline.observe('read_file', { filePath: '/tmp/c.txt', encoding: 'utf-8' });

      const profile = baseline.profiles.get('read_file')!;
      expect(profile.typicalArgs.get('filePath')!.count).toBe(3);
      expect(profile.typicalArgs.get('encoding')!.count).toBe(1);
    });

    it('computes average argument size', () => {
      baseline.observe('write_file', { filePath: '/tmp/short.txt', content: 'hi' });
      baseline.observe('write_file', {
        filePath: '/tmp/long.txt',
        content: 'this is a much longer string of text for testing purposes',
      });

      const profile = baseline.profiles.get('write_file')!;
      expect(profile.avgArgSize).toBeGreaterThan(0);
    });

    it('handles multiple different tools', () => {
      baseline.observe('read_file', { filePath: '/tmp/test.txt' });
      baseline.observe('write_file', { filePath: '/tmp/output.txt', content: 'data' });
      baseline.observe('bash_exec', { command: 'ls -la' });

      expect(baseline.profiles.size).toBe(3);
      expect(baseline.profiles.has('read_file')).toBe(true);
      expect(baseline.profiles.has('write_file')).toBe(true);
      expect(baseline.profiles.has('bash_exec')).toBe(true);
    });
  });

  describe('detectDeviation', () => {
    const buildBaseline = (toolName: string, callCount: number = 100) => {
      const bl = new BehavioralBaseline();
      for (let i = 0; i < callCount; i++) {
        bl.observe(toolName, {
          filePath: `/tmp/file_${i % 5}.txt`,
          encoding: 'utf-8',
        });
      }
      return bl;
    };

    it('reports new_tool for a never-seen tool', () => {
      const deviations = baseline.detectDeviation('unknown_tool', {});
      expect(deviations.length).toBe(1);
      expect(deviations[0].type).toBe('new_tool');
      expect(deviations[0].severity).toBe('info');
    });

    it('returns empty deviations when below baseline window', () => {
      baseline.observe('read_file', { filePath: '/tmp/test.txt' });
      const deviations = baseline.detectDeviation('read_file', { filePath: '/tmp/test.txt' });
      expect(deviations).toEqual([]);
    });

    it('detects new argument keys after baseline is established', () => {
      const bl = buildBaseline('read_file');
      const deviations = bl.detectDeviation('read_file', {
        filePath: '/tmp/test.txt',
        encoding: 'utf-8',
        newUnexpectedArg: 'suspicious_value',
      });
      const newArgDeviations = deviations.filter((d) => d.type === 'new_args');
      expect(newArgDeviations.length).toBe(1);
      expect(newArgDeviations[0].severity).toBe('warn');
      expect(newArgDeviations[0].detail).toContain('newUnexpectedArg');
    });

    it('detects size anomaly when args are much larger than average', () => {
      const bl = new BehavioralBaseline();
      for (let i = 0; i < 100; i++) {
        bl.observe('write_file', { filePath: '/tmp/short.txt', content: 'x' });
      }

      const deviations = bl.detectDeviation('write_file', {
        filePath: '/tmp/giant.txt',
        content: 'x'.repeat(10000),
      });
      const sizeDeviations = deviations.filter((d) => d.type === 'size_anomaly');
      expect(sizeDeviations.length).toBe(1);
      expect(sizeDeviations[0].severity).toBe('warn');
    });

    it('does not report size anomaly when within normal range', () => {
      const bl = new BehavioralBaseline();
      for (let i = 0; i < 100; i++) {
        bl.observe('write_file', {
          filePath: '/tmp/file.txt',
          content: 'a'.repeat(500),
        });
      }

      const deviations = bl.detectDeviation('write_file', {
        filePath: '/tmp/file.txt',
        content: 'a'.repeat(600),
      });
      const sizeDeviations = deviations.filter((d) => d.type === 'size_anomaly');
      expect(sizeDeviations).toEqual([]);
    });

    it('detects new args when previously unseen keys appear', () => {
      const bl = buildBaseline('api_call');
      const deviations = bl.detectDeviation('api_call', {
        filePath: '/tmp/test.txt',
        encoding: 'utf-8',
        secretToken: 'abc123',
        callbackUrl: 'https://evil.com/steal',
      });
      const newArgDeviations = deviations.filter((d) => d.type === 'new_args');
      expect(newArgDeviations.length).toBe(1);
      expect(newArgDeviations[0].detail).toContain('secretToken');
      expect(newArgDeviations[0].detail).toContain('callbackUrl');
    });
  });

  describe('generateReport', () => {
    it('returns empty message when no profiles exist', () => {
      const report = baseline.generateReport();
      expect(report).toContain('No behavioral data collected');
    });

    it('includes tool names in the report', () => {
      baseline.observe('read_file', { filePath: '/tmp/test.txt' });
      baseline.observe('write_file', { filePath: '/tmp/output.txt', content: 'data' });

      const report = baseline.generateReport();
      expect(report).toContain('read_file');
      expect(report).toContain('write_file');
    });

    it('includes call counts in the report', () => {
      for (let i = 0; i < 5; i++) {
        baseline.observe('read_file', { filePath: '/tmp/test.txt' });
      }

      const report = baseline.generateReport();
      expect(report).toContain('Calls: 5');
    });

    it('includes typical args in the report', () => {
      baseline.observe('read_file', { filePath: '/tmp/test.txt', encoding: 'utf-8' });
      baseline.observe('read_file', { filePath: '/tmp/test.txt', encoding: 'utf-8' });

      const report = baseline.generateReport();
      expect(report).toContain('Typical args:');
      expect(report).toContain('filePath');
    });

    it('includes first seen and last seen timestamps', () => {
      baseline.observe('read_file', { filePath: '/tmp/test.txt' });

      const report = baseline.generateReport();
      expect(report).toContain('First seen:');
      expect(report).toContain('Last seen:');
    });

    it('includes normal hours in the report', () => {
      baseline.observe('read_file', { filePath: '/tmp/test.txt' });

      const report = baseline.generateReport();
      expect(report).toContain('Normal hours:');
    });

    it('sorts tools by call count descending', () => {
      for (let i = 0; i < 10; i++) {
        baseline.observe('rare_tool', { key: 'value' });
      }
      for (let i = 0; i < 50; i++) {
        baseline.observe('frequent_tool', { key: 'value' });
      }

      const report = baseline.generateReport();
      const frequentIndex = report.indexOf('frequent_tool');
      const rareIndex = report.indexOf('rare_tool');
      expect(frequentIndex).toBeLessThan(rareIndex);
    });

    it('shows "no pattern" when no clear hour pattern exists', () => {
      baseline.observe('read_file', { filePath: '/tmp/test.txt' });

      const report = baseline.generateReport();
      expect(report).toContain('Normal hours:');
    });
  });
});
