import { Request, Response, NextFunction, RequestHandler } from 'express';

export interface Parry_DDoSOptions {
  /** Enables SQL injection detection. Default: true */
  sql?: boolean;
  /** Enables XSS detection. Default: true */
  xss?: boolean;
  /** Enables NoSQL injection detection. Default: true */
  nosql?: boolean;
  /** Enables rate limiting by IP. Default: true */
  rateLimit?: boolean;
  /** Maximum number of requests per time window per IP. Default: 100 */
  maxRequests?: number;
  /** Duration of the rate limiting window in ms. Default: 60000 */
  windowMs?: number;
  /** Suspicious attempts before temporary ban. Default: 5 */
  suspiciousThreshold?: number;
  /** Duration of the ban in ms. Default: 300000 (5 min) */
  banDurationMs?: number;
  /** Displays colored threat logs in the console. Default: true */
  logThreats?: boolean;
  /** Callback triggered for each detected threat */
  onThreat?: (entry: ThreatLogEntry, req: Request, res: Response) => void;
}

export type DetectorType = 'SQL_INJECTION' | 'XSS' | 'NOSQL_INJECTION';

export interface ThreatMatch {
  detector: DetectorType;
  field: string;
  pattern: string;
}

export type LogEntryType = 'THREAT' | 'BAN' | 'RATE_LIMIT';

export interface ThreatLogEntry {
  type: LogEntryType;
  ip: string;
  timestamp: string;
  method?: string;
  url?: string;
  reason?: string;
  threats?: ThreatMatch[];
}

export interface RateLimitResult {
  limited: boolean;
  banned: boolean;
  remaining: number;
  resetAt: number;
  banExpiresAt: number | null;
}

export interface IPSnapshot {
  ip: string;
  requests: number;
  suspicious: number;
  banned: boolean;
  banExpiresAt: number | null;
}

export declare class RateLimiter {
  constructor(
    config: Pick<
      Parry_DDoSOptions,
      'maxRequests' | 'windowMs' | 'suspiciousThreshold' | 'banDurationMs'
    >
  );
  check(ip: string): RateLimitResult;
  recordSuspicious(ip: string): void;
  unban(ip: string): void;
  snapshot(): IPSnapshot[];
  destroy(): void;
}

export declare const SQLInjectionDetector: {
  scan(value: string): string | null;
};
export declare const XSSDetector: { scan(value: string): string | null };
export declare const NoSQLDetector: { scan(value: unknown): string | null };

export declare function Parry_DDoS(options?: Parry_DDoSOptions): RequestHandler;
