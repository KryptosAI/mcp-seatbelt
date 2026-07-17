export interface ThreatIntelResult {
  malicious: boolean;
  source: string;
  queryType: "ip" | "domain" | "hash";
  queryValue: string;
  details: string;
}

let cache: Map<string, { result: ThreatIntelResult; expires: number }> = new Map();
const CACHE_TTL = 3600_000;
const THREATFOX_API = "https://threatfox.abuse.ch/api/v1/";

async function queryThreatFox(type: string, value: string): Promise<ThreatIntelResult | null> {
  const cacheKey = `${type}:${value}`;
  const cached = cache.get(cacheKey);
  if (cached && cached.expires > Date.now()) return cached.result;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const res = await fetch(THREATFOX_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "search_ioc", search_term: value }),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) return null;
    const data = await res.json() as Record<string, unknown>;
    const malicious = data.query_status === "ok" && Array.isArray(data.data) && (data.data as unknown[]).length > 0;

    const result: ThreatIntelResult = {
      malicious,
      source: "threatfox",
      queryType: type as "ip" | "domain" | "hash",
      queryValue: value,
      details: malicious ? `Found in ${(data.data as unknown[]).length} IOC entries` : "Not found",
    };

    cache.set(cacheKey, { result, expires: Date.now() + CACHE_TTL });
    return result;
  } catch {
    return null;
  }
}

export async function checkThreatIntel(args: Record<string, unknown>): Promise<ThreatIntelResult[]> {
  const results: ThreatIntelResult[] = [];

  for (const [key, value] of Object.entries(args)) {
    if (typeof value !== "string") continue;

    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) {
      const r = await queryThreatFox("ip", value);
      if (r) results.push(r);
    } else if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value) && !value.includes("@") && !value.startsWith(".")) {
      const r = await queryThreatFox("domain", value);
      if (r) results.push(r);
    }
  }

  return results;
}

export function getCache(): Map<string, { result: ThreatIntelResult; expires: number }> {
  return cache;
}

export function clearCache(): void {
  cache.clear();
}
