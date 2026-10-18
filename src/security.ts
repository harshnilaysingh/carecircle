import { createHmac, randomBytes } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { config, isProduction } from './config.js';

export function digest(value: string, key = config.SESSION_HASH_KEY): string {
  return createHmac('sha256', key).update(value).digest('hex');
}

export function newToken(): string {
  return randomBytes(32).toString('base64url');
}

export function setSessionCookie(reply: FastifyReply, token: string): void {
  reply.setCookie(config.SESSION_COOKIE_NAME, token, {
    httpOnly: true, secure: isProduction, sameSite: 'strict', path: '/',
    maxAge: config.SESSION_TTL_DAYS * 24 * 60 * 60,
  });
}

export function clearSessionCookie(reply: FastifyReply): void {
  reply.clearCookie(config.SESSION_COOKIE_NAME, { httpOnly: true, secure: isProduction, sameSite: 'strict', path: '/' });
}

export function requireSameOrigin(request: FastifyRequest): boolean {
  const origin = request.headers.origin;
  return typeof origin === 'string' && origin === config.APP_ORIGIN;
}
