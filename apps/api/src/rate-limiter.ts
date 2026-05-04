import type { FastifyRequest } from "fastify";

export type RateLimitDecision =
  | { allowed: true }
  | { allowed: false; retryAfterMs: number };

export type RateLimitRule = {
  name: string;
  limit: number;
  windowMs: number;
  match: (request: FastifyRequest) => boolean;
  key: (request: FastifyRequest) => string;
};

export type RateLimiter = {
  consume(rule: RateLimitRule, key: string): Promise<RateLimitDecision>;
};

export type RedisLikeRateLimitClient = {
  incr(key: string): Promise<number>;
  pexpire(key: string, milliseconds: number): Promise<unknown>;
  pttl(key: string): Promise<number>;
};

export class InMemoryRateLimiter implements RateLimiter {
  private readonly store = new Map<string, { count: number; resetAt: number }>();

  async consume(rule: RateLimitRule, key: string): Promise<RateLimitDecision> {
    const now = Date.now();
    const existing = this.store.get(key);

    if (!existing || existing.resetAt <= now) {
      this.store.set(key, { count: 1, resetAt: now + rule.windowMs });
      return { allowed: true };
    }

    if (existing.count >= rule.limit) {
      return { allowed: false, retryAfterMs: existing.resetAt - now };
    }

    existing.count += 1;
    return { allowed: true };
  }
}

export class RedisRateLimiter implements RateLimiter {
  constructor(private readonly client: RedisLikeRateLimitClient) {}

  async consume(rule: RateLimitRule, key: string): Promise<RateLimitDecision> {
    const count = await this.client.incr(key);

    if (count === 1) {
      await this.client.pexpire(key, rule.windowMs);
    }

    if (count <= rule.limit) {
      return { allowed: true };
    }

    const ttl = await this.client.pttl(key);

    return { allowed: false, retryAfterMs: ttl > 0 ? ttl : rule.windowMs };
  }
}
