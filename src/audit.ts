import { createHmac } from 'node:crypto';
import { appendFile, readFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { existsSync } from 'node:fs';

export interface SignedAuditEntry {
  _seq: number;
  _hmac: string;
  toolName: string;
  description: string;
  args: Record<string, unknown>;
  action: 'allow' | 'deny' | 'warn' | 'redact';
  timestamp: string;
  reason: string;
  context?: { client: string; requestCount: number };
}

export interface AuditEntryInput {
  toolName: string;
  description: string;
  args: Record<string, unknown>;
  action: 'allow' | 'deny' | 'warn' | 'redact';
  timestamp: string;
  reason: string;
  context?: { client: string; requestCount: number };
}

export interface VerifyResult {
  valid: boolean;
  total: number;
  tampered: number;
}

export interface AuditQuery {
  since?: Date;
  tool?: string;
  action?: string;
}

export class AuditTrail {
  private logPath: string;
  private secret: string;
  private seq: number = 0;
  private writeLock: Promise<void> = Promise.resolve();

  constructor(logPath: string, secret: string) {
    this.logPath = logPath;
    this.secret = secret;
  }

  async append(entry: AuditEntryInput): Promise<void> {
    const done = this.writeLock.then(async () => {
      const dir = dirname(this.logPath);
      if (!existsSync(dir)) {
        await mkdir(dir, { recursive: true });
      }

      const signed: SignedAuditEntry = {
        _seq: this.seq,
        _hmac: '',
        ...entry,
      };

      signed._hmac = this.computeHmac(this.seq, entry);

      const line = JSON.stringify(signed) + '\n';
      await appendFile(this.logPath, line, 'utf-8');
      this.seq++;
    });

    this.writeLock = done.catch(() => {});
    return done;
  }

  async verify(): Promise<VerifyResult> {
    let total = 0;
    let tampered = 0;

    if (!existsSync(this.logPath)) {
      return { valid: true, total: 0, tampered: 0 };
    }

    const entries = await this.readAllEntries();
    for (const entry of entries) {
      total++;
      const { _seq, _hmac, ...rest } = entry;
      const expected = this.computeHmac(_seq, rest as AuditEntryInput);
      if (_hmac !== expected) {
        tampered++;
      }
    }

    return {
      valid: tampered === 0,
      total,
      tampered,
    };
  }

  async query(filters: AuditQuery): Promise<SignedAuditEntry[]> {
    const entries = await this.readAllEntries();

    return entries.filter((entry) => {
      if (filters.since) {
        const entryTime = new Date(entry.timestamp).getTime();
        if (entryTime < filters.since.getTime()) return false;
      }
      if (filters.tool && entry.toolName !== filters.tool) return false;
      if (filters.action && entry.action !== filters.action) return false;
      return true;
    });
  }

  private computeHmac(seq: number, entry: AuditEntryInput): string {
    const hmac = createHmac('sha256', this.secret);
    hmac.update(String(seq) + JSON.stringify(entry));
    return hmac.digest('hex');
  }

  private async readAllEntries(): Promise<SignedAuditEntry[]> {
    const entries: SignedAuditEntry[] = [];

    if (!existsSync(this.logPath)) {
      return entries;
    }

    return new Promise((resolve, reject) => {
      const rl = createInterface({
        input: createReadStream(this.logPath),
        crlfDelay: Infinity,
      });

      rl.on('line', (line: string) => {
        const trimmed = line.trim();
        if (!trimmed) return;
        try {
          const entry = JSON.parse(trimmed) as SignedAuditEntry;
          entries.push(entry);
        } catch {
          // skip unparseable lines
        }
      });

      rl.on('close', () => {
        resolve(entries);
      });

      rl.on('error', reject);
    });
  }
}

export async function verifyAuditFile(logPath: string, secret: string): Promise<VerifyResult> {
  const trail = new AuditTrail(logPath, secret);
  return trail.verify();
}

export function computeHmacStatic(seq: number, entry: AuditEntryInput, secret: string): string {
  const hmac = createHmac('sha256', secret);
  hmac.update(String(seq) + JSON.stringify(entry));
  return hmac.digest('hex');
}
