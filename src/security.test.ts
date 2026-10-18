import { describe, expect, it } from 'vitest';
import { digest, newToken } from './security.js';

describe('session token helpers', () => {
  it('creates opaque high-entropy URL-safe tokens', () => {
    const token = newToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    expect(newToken()).not.toBe(token);
  });

  it('stores keyed digests rather than raw bearer tokens', () => {
    expect(digest('example-token', 'a'.repeat(32))).toHaveLength(64);
    expect(digest('example-token', 'a'.repeat(32))).not.toBe('example-token');
    expect(digest('example-token', 'a'.repeat(32))).not.toBe(digest('example-token', 'b'.repeat(32)));
  });
});
