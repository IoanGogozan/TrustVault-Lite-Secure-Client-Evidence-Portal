import { describe, expect, it } from "vitest";
import { RedisRateLimiter, type RedisLikeRateLimitClient } from "./rate-limiter.js";

describe("RedisRateLimiter", () => {
  it("uses Redis-like counters and returns retry timing when limited", async () => {
    const counts = new Map<string, number>();
    const expires = new Map<string, number>();
    const client: RedisLikeRateLimitClient = {
      async incr(key) {
        const nextCount = (counts.get(key) ?? 0) + 1;
        counts.set(key, nextCount);
        return nextCount;
      },
      async pexpire(key, milliseconds) {
        expires.set(key, milliseconds);
      },
      async pttl(key) {
        return expires.get(key) ?? -1;
      }
    };
    const limiter = new RedisRateLimiter(client);
    const rule = {
      name: "test",
      limit: 2,
      windowMs: 60_000,
      match: () => true,
      key: () => "subject"
    };

    await expect(limiter.consume(rule, "test:subject")).resolves.toEqual({ allowed: true });
    await expect(limiter.consume(rule, "test:subject")).resolves.toEqual({ allowed: true });
    await expect(limiter.consume(rule, "test:subject")).resolves.toEqual({
      allowed: false,
      retryAfterMs: 60_000
    });
  });
});
