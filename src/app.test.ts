import { afterEach, describe, expect, it } from 'vitest';
import { buildApp } from './app.js';
import type { FastifyInstance } from 'fastify';

describe('HTTP boundary', () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => { if (app) await app.close(); app = undefined; });

  it('exposes liveness without exposing application data', async () => {
    app = await buildApp();
    const response = await app.inject({ method: 'GET', url: '/healthz' });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'ok' });
    expect(response.headers['cache-control']).toBe('no-store');
  });

  it('rejects unauthenticated access before querying protected routes', async () => {
    app = await buildApp();
    const response = await app.inject({ method: 'GET', url: '/api/auth/me' });
    expect(response.statusCode).toBe(401);
    expect(response.json().error.code).toBe('AUTHENTICATION_REQUIRED');
  });

  it('rejects cross-origin state changes before route handling', async () => {
    app = await buildApp();
    const response = await app.inject({ method: 'POST', url: '/api/families', headers: { origin: 'https://attacker.example' }, payload: { name: 'Private family' } });
    expect(response.statusCode).toBe(403);
    expect(response.json().error.code).toBe('ORIGIN_REJECTED');
  });

  it('returns a stable 429 response when an authentication limit is exceeded', async () => {
    app = await buildApp();
    let response;
    for (let index = 0; index < 6; index += 1) response = await app.inject({ method: 'POST', url: '/api/auth/login', payload: {} });
    expect(response!.statusCode).toBe(429);
    expect(response!.json().error.code).toBe('RATE_LIMITED');
  });
});
