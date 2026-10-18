import Fastify, { type FastifyReply, type FastifyRequest } from 'fastify';
import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import argon2 from 'argon2';
import { Redis } from 'ioredis';
import { z } from 'zod';
import { Prisma, PrismaClient, BillingProvider, FamilyRole, FamilyStatus, InviteStatus, PurchaseStatus, PurchaseType, RecordKind } from '@prisma/client';
import { config } from './config.js';
import { clearSessionCookie, digest, newToken, requireSameOrigin, setSessionCookie } from './security.js';
import { capturePayPalOrder, createPayPalOrder, getPayPalOrder, PayPalRequestError, verifyPayPalWebhook, type PayPalCredentials, type PayPalOrder, type PayPalWebhookEvent } from './payments.js';
import { careCircleHtml } from './web.js';

const prisma = new PrismaClient({ log: config.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'] });
declare module 'fastify' { interface FastifyRequest { userId?: string; } }

const emailSchema = z.string().trim().email().max(320).transform(v => v.toLowerCase());
const registration = z.object({ email: emailSchema, password: z.string().min(12).max(128), displayName: z.string().trim().min(1).max(120), inviteCode: z.string().min(32).max(128).optional() }).strict();
const login = z.object({ email: emailSchema, password: z.string().min(1).max(128), inviteCode: z.string().min(32).max(128).optional() }).strict();
const invitationInput = z.object({ email: emailSchema, role: z.enum(['ADMIN', 'CAREGIVER', 'VIEWER']).default('CAREGIVER') }).strict();
const inviteCodeInput = z.object({ code: z.string().min(32).max(128) }).strict();
const extraSeatsInput = z.object({ quantity: z.number().int().min(1).max(100) }).strict();
const recordInput = z.object({ kind: z.nativeEnum(RecordKind), title: z.string().trim().min(1).max(200), data: z.record(z.string(), z.unknown()) }).strict();
const recordKinds = new Set(Object.values(RecordKind));
const safeUser = (u: { id: string; email: string; displayName: string }) => ({ id: u.id, email: u.email, displayName: u.displayName });
const fail = (reply: FastifyReply, status: number, code: string) => reply.code(status).send({ error: { code } });
const isAdmin = (role: FamilyRole) => role === FamilyRole.OWNER || role === FamilyRole.ADMIN;
class FamilyInviteError extends Error {
  constructor(readonly code: 'INVITATION_INVALID' | 'ACTIVE_FAMILY_REQUIRED' | 'ALREADY_IN_FAMILY' | 'SEATS_FULL') { super(code); }
}

async function acceptInviteInTransaction(tx: Prisma.TransactionClient, userId: string, code: string, requestId: string): Promise<{ familyId: string }> {
  const codeHash = digest(code, config.INVITATION_HASH_KEY);
  const initial = await tx.invite.findUnique({ where: { codeHash } });
  if (!initial) throw new FamilyInviteError('INVITATION_INVALID');

  // Serialize seat allocations for this family. The member count and insert are
  // inside the same transaction after the family row lock, so the last seat can
  // only be claimed once even when multiple invite links are redeemed together.
  const locked = await tx.$queryRaw<Array<{ id: string }>>`SELECT "id" FROM "families" WHERE "id" = ${initial.familyId} FOR UPDATE`;
  if (locked.length !== 1) throw new FamilyInviteError('INVITATION_INVALID');
  const [family, invite] = await Promise.all([
    tx.family.findUnique({ where: { id: initial.familyId } }),
    tx.invite.findUnique({ where: { id: initial.id } }),
  ]);
  const now = new Date();
  if (!family || !invite || invite.status !== InviteStatus.PENDING || invite.expiresAt <= now) throw new FamilyInviteError('INVITATION_INVALID');
  if (family.status !== FamilyStatus.ACTIVE) throw new FamilyInviteError('ACTIVE_FAMILY_REQUIRED');
  if (invite.email) {
    const invitedUser = await tx.user.findUnique({ where: { id: userId }, select: { email: true } });
    if (!invitedUser || invitedUser.email.toLowerCase() !== invite.email.toLowerCase()) throw new FamilyInviteError('INVITATION_INVALID');
  }
  if (await tx.familyMember.findUnique({ where: { userId }, select: { id: true } })) throw new FamilyInviteError('ALREADY_IN_FAMILY');
  const usedSeats = await tx.familyMember.count({ where: { familyId: family.id } });
  if (usedSeats >= family.seatLimit) throw new FamilyInviteError('SEATS_FULL');

  const claim = await tx.invite.updateMany({ where: { id: invite.id, status: InviteStatus.PENDING, expiresAt: { gt: now } }, data: { status: InviteStatus.ACCEPTED, acceptedAt: now } });
  if (claim.count !== 1) throw new FamilyInviteError('INVITATION_INVALID');
  await tx.familyMember.create({ data: { familyId: family.id, userId, role: invite.role } });
  await tx.auditEvent.create({ data: { actorId: userId, action: 'family.invite.accepted', familyId: family.id, subjectType: 'invite', subjectId: invite.id, requestId } });
  return { familyId: family.id };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function textValue(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function amountCents(value: string): number {
  const [whole, fraction = ''] = value.split('.');
  return Number(whole) * 100 + Number(fraction.padEnd(2, '0'));
}

function amountForQuantity(unitAmount: string, quantity: number): string {
  const total = amountCents(unitAmount) * quantity;
  return `${Math.floor(total / 100)}.${String(total % 100).padStart(2, '0')}`;
}

export async function buildApp() {
  const app = Fastify({ logger: { level: config.NODE_ENV === 'development' ? 'debug' : 'info', redact: ['req.headers.cookie', 'req.headers.authorization', 'res.headers["set-cookie"]'] }, bodyLimit: 32 * 1024, trustProxy: config.TRUST_PROXY, requestIdHeader: 'x-request-id', genReqId: () => newToken().slice(0, 22) });
  const redis = config.REDIS_URL ? new Redis(config.REDIS_URL, { connectTimeout: 10000, maxRetriesPerRequest: 1, enableOfflineQueue: false }) : undefined;
  redis?.on('error', error => app.log.error({ errorName: error.name }, 'rate limit store connection failed'));
  await app.register(helmet, { contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: 'same-site' } });
  await app.register(cors, { origin: config.APP_ORIGIN, credentials: true, methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'], allowedHeaders: ['content-type', 'x-csrf-token', 'x-request-id'] });
  await app.register(cookie);
  await app.register(rateLimit, { max: 120, timeWindow: '1 minute', ...(redis ? { redis } : {}) });

  app.addHook('onRequest', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    if (['POST', 'PATCH', 'DELETE'].includes(request.method) && request.url !== '/api/auth/login' && request.url !== '/api/auth/register' && request.url !== '/api/auth/invitations/accept' && !request.url.startsWith('/api/billing/paypal/webhook') && !requireSameOrigin(request)) {
      await fail(reply, 403, 'ORIGIN_REJECTED');
    }
  });
  app.setErrorHandler((error, request, reply) => {
    request.log.error({ requestId: request.id, errorName: error instanceof Error ? error.name : 'unknown', ...(error instanceof Prisma.PrismaClientKnownRequestError ? { errorCode: error.code } : {}) }, 'request failed');
    if (error instanceof z.ZodError) return reply.code(400).send({ error: { code: 'VALIDATION_ERROR', details: error.issues.map(i => ({ path: i.path.join('.'), code: i.code })) } });
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') return fail(reply, 409, 'CONFLICT');
    const statusCode = typeof error === 'object' && error !== null && 'statusCode' in error && typeof error.statusCode === 'number' ? error.statusCode : 500;
    if (statusCode >= 400 && statusCode < 500) return fail(reply, statusCode, statusCode === 429 ? 'RATE_LIMITED' : 'REQUEST_REJECTED');
    return fail(reply, 500, 'INTERNAL_ERROR');
  });

  const auth = async (request: FastifyRequest, reply: FastifyReply) => {
    const token = request.cookies[config.SESSION_COOKIE_NAME];
    if (!token) return fail(reply, 401, 'AUTHENTICATION_REQUIRED');
    const session = await prisma.session.findUnique({ where: { tokenHash: digest(token) }, include: { user: { select: { id: true } } } });
    if (!session || session.expiresAt <= new Date()) {
      if (session) await prisma.session.delete({ where: { id: session.id } }).catch(() => undefined);
      clearSessionCookie(reply);
      return fail(reply, 401, 'SESSION_EXPIRED');
    }
    request.userId = session.user.id;
  };
  const membership = async (request: FastifyRequest, reply: FastifyReply, familyId: string) => {
    if (!request.userId) return null;
    const m = await prisma.familyMember.findUnique({ where: { familyId_userId: { familyId, userId: request.userId } }, include: { family: { select: { status: true } } } });
    if (!m) { await fail(reply, 404, 'FAMILY_NOT_FOUND'); return null; }
    if (m.family.status !== FamilyStatus.ACTIVE) { await fail(reply, 402, 'ACTIVE_FAMILY_REQUIRED'); return null; }
    return m;
  };
  const audit = async (actorId: string | null, action: string, familyId?: string, subjectType?: string, subjectId?: string, requestId?: string) => {
    await prisma.auditEvent.create({ data: { actorId, action, ...(familyId ? { familyId } : {}), ...(subjectType ? { subjectType } : {}), ...(subjectId ? { subjectId } : {}), ...(requestId ? { requestId } : {}) } });
  };
  const createInvite = async (familyId: string, createdById: string, role: FamilyRole, requestId: string, email?: string) => {
    const code = newToken();
    const invite = await prisma.$transaction(async tx => {
      const created = await tx.invite.create({ data: { familyId, ...(email ? { email } : {}), role, codeHash: digest(code, config.INVITATION_HASH_KEY), createdById, expiresAt: new Date(Date.now() + 7 * 86400000) } });
      await tx.auditEvent.create({ data: { actorId: createdById, action: 'family.invite.created', familyId, subjectType: 'invite', subjectId: created.id, requestId } });
      return created;
    });
    return { invite, code, inviteUrl: `${config.PUBLIC_APP_URL}/invite?code=${encodeURIComponent(code)}` };
  };

  app.get('/', async (_request, reply) => reply.type('text/html; charset=utf-8').header('Cache-Control', 'no-store').send(careCircleHtml));
  app.get('/invite', async (_request, reply) => reply.type('text/html; charset=utf-8').header('Cache-Control', 'no-store').send(careCircleHtml));
  app.get('/healthz', async () => ({ status: 'ok' }));
  app.get('/readyz', async (_request, reply) => {
    try { await prisma.$queryRaw`SELECT 1`; if (redis) await redis.ping(); return { status: 'ready' }; }
    catch { return fail(reply, 503, 'DEPENDENCY_UNAVAILABLE'); }
  });

  app.post('/api/auth/register', { config: { rateLimit: { max: 5, timeWindow: '15 minutes' } } }, async (request, reply) => {
    const input = registration.parse(request.body);
    const passwordHash = await argon2.hash(input.password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
    const token = newToken();
    let result: { user: { id: string; email: string; displayName: string }; familyId: string | null };
    try {
      result = await prisma.$transaction(async tx => {
        const user = await tx.user.create({ data: { email: input.email, passwordHash, displayName: input.displayName }, select: { id: true, email: true, displayName: true } });
        const familyId = input.inviteCode ? (await acceptInviteInTransaction(tx, user.id, input.inviteCode, request.id)).familyId : null;
        await tx.session.create({ data: { tokenHash: digest(token), userId: user.id, expiresAt: new Date(Date.now() + config.SESSION_TTL_DAYS * 86400000) } });
        await tx.auditEvent.create({ data: { actorId: user.id, action: 'auth.register', ...(familyId ? { familyId } : {}), subjectType: 'user', subjectId: user.id, requestId: request.id } });
        return { user, familyId };
      });
    } catch (error) {
      if (error instanceof FamilyInviteError) return fail(reply, error.code === 'ACTIVE_FAMILY_REQUIRED' ? 402 : 400, error.code);
      throw error;
    }
    setSessionCookie(reply, token);
    return reply.code(201).send({ user: safeUser(result.user), familyId: result.familyId, access: { granted: result.familyId !== null } });
  });

  app.post('/api/auth/login', { config: { rateLimit: { max: 5, timeWindow: '15 minutes' } } }, async (request, reply) => {
    const input = login.parse(request.body);
    const user = await prisma.user.findUnique({ where: { email: input.email } });
    const valid = user ? await argon2.verify(user.passwordHash, input.password) : false;
    if (!user || !valid) return fail(reply, 401, 'INVALID_CREDENTIALS');
    const token = newToken();
    const expiresAt = new Date(Date.now() + config.SESSION_TTL_DAYS * 86400000);
    let familyId: string | null = null;
    try {
      await prisma.$transaction(async tx => {
        if (input.inviteCode) familyId = (await acceptInviteInTransaction(tx, user.id, input.inviteCode, request.id)).familyId;
        else {
          const existing = await tx.familyMember.findUnique({ where: { userId: user.id }, include: { family: { select: { id: true } } } });
          familyId = existing?.family.id ?? null;
        }
        await tx.session.create({ data: { tokenHash: digest(token), userId: user.id, expiresAt } });
        await tx.auditEvent.create({ data: { actorId: user.id, action: 'auth.login', ...(familyId ? { familyId } : {}), subjectType: 'user', subjectId: user.id, requestId: request.id } });
      });
    } catch (error) {
      if (error instanceof FamilyInviteError) return fail(reply, error.code === 'ACTIVE_FAMILY_REQUIRED' ? 402 : 400, error.code);
      throw error;
    }
    setSessionCookie(reply, token);
    const activeFamily = familyId ? await prisma.family.findUnique({ where: { id: familyId }, select: { id: true, status: true } }) : null;
    return { user: safeUser(user), expiresAt, familyId, access: { granted: activeFamily?.status === FamilyStatus.ACTIVE } };
  });

  app.post('/api/auth/logout', { preHandler: auth }, async (request, reply) => {
    const token = request.cookies[config.SESSION_COOKIE_NAME];
    if (token) await prisma.session.deleteMany({ where: { tokenHash: digest(token) } });
    await audit(request.userId!, 'auth.logout', undefined, 'user', request.userId, request.id);
    clearSessionCookie(reply);
    return reply.code(204).send();
  });

  app.get('/api/auth/me', { preHandler: auth }, async request => {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: request.userId! }, select: { id: true, email: true, displayName: true } });
    const families = await prisma.familyMember.findMany({ where: { userId: user.id }, include: { family: { select: { id: true, name: true, status: true, seatLimit: true, ownerId: true } } } });
    const active = families.find(item => item.family.status === FamilyStatus.ACTIVE);
    return { user: safeUser(user), families, access: { granted: Boolean(active), familyId: active?.family.id ?? null, reason: active ? null : 'ACTIVE_FAMILY_REQUIRED' } };
  });

  app.post('/api/families', { preHandler: auth }, async (request, reply) => {
    return fail(reply, 402, 'FAMILY_PURCHASE_REQUIRED');
  });

  app.get('/api/families/:familyId/members', { preHandler: auth }, async (request, reply) => {
    const { familyId } = request.params as { familyId: string };
    const member = await membership(request, reply, familyId); if (!member) return;
    return prisma.familyMember.findMany({ where: { familyId }, include: { user: { select: { id: true, email: true, displayName: true } } } });
  });

  app.post('/api/families/:familyId/invitations', { preHandler: auth, config: { rateLimit: { max: 10, timeWindow: '1 hour' } } }, async (request, reply) => {
    const { familyId } = request.params as { familyId: string };
    const member = await membership(request, reply, familyId); if (!member) return;
    if (member.role !== FamilyRole.OWNER) return fail(reply, 403, 'ROLE_FORBIDDEN');
    const input = invitationInput.parse(request.body);
    if (config.NODE_ENV === 'production' && (!config.RESEND_API_KEY || !config.EMAIL_FROM)) return fail(reply, 503, 'INVITATION_DELIVERY_NOT_CONFIGURED');
    const { invite, inviteUrl } = await createInvite(familyId, request.userId!, input.role as FamilyRole, request.id, input.email);
    if (config.NODE_ENV === 'production') {
      try {
        const response = await fetch('https://api.resend.com/emails', {
          method: 'POST', headers: { authorization: `Bearer ${config.RESEND_API_KEY!}`, 'content-type': 'application/json', 'idempotency-key': `carecircle-invitation-${invite.id}` },
          body: JSON.stringify({ from: config.EMAIL_FROM!, to: [input.email], subject: 'You are invited to a CareCircle family workspace', html: `<p>You have been invited to join a family care workspace.</p><p><a href="${inviteUrl}">Accept invitation</a></p><p>This link expires in 7 days. If you were not expecting this invitation, you can ignore this message.</p>` }),
          signal: AbortSignal.timeout(8000),
        });
        if (!response.ok) throw new Error('email provider rejected invitation');
      } catch {
        await prisma.invite.update({ where: { id: invite.id }, data: { status: InviteStatus.REVOKED, revokedAt: new Date() } });
        return fail(reply, 503, 'INVITATION_DELIVERY_FAILED');
      }
      return reply.code(201).send({ id: invite.id, expiresAt: invite.expiresAt, delivery: 'sent' });
    }
    return reply.code(201).send({ id: invite.id, inviteUrl, expiresAt: invite.expiresAt, delivery: 'development-only' });
  });

  app.post('/api/families/:familyId/invites', { preHandler: auth, config: { rateLimit: { max: 10, timeWindow: '1 hour' } } }, async (request, reply) => {
    const { familyId } = request.params as { familyId: string };
    const member = await membership(request, reply, familyId); if (!member) return;
    if (member.role !== FamilyRole.OWNER) return fail(reply, 403, 'ROLE_FORBIDDEN');
    z.object({}).strict().parse(request.body ?? {});
    const { invite, code, inviteUrl } = await createInvite(familyId, request.userId!, FamilyRole.CAREGIVER, request.id);
    return reply.code(201).send({ id: invite.id, code, inviteUrl, expiresAt: invite.expiresAt, status: invite.status });
  });

  app.get('/api/families/:familyId/seat-management', { preHandler: auth }, async (request, reply) => {
    const { familyId } = request.params as { familyId: string };
    const member = await membership(request, reply, familyId); if (!member) return;
    if (member.role !== FamilyRole.OWNER) return fail(reply, 403, 'ROLE_FORBIDDEN');
    const [family, members, invites] = await Promise.all([
      prisma.family.findUniqueOrThrow({ where: { id: familyId }, select: { id: true, name: true, ownerId: true, status: true, seatLimit: true } }),
      prisma.familyMember.findMany({ where: { familyId }, include: { user: { select: { id: true, email: true, displayName: true } } }, orderBy: { createdAt: 'asc' } }),
      prisma.invite.findMany({ where: { familyId, status: InviteStatus.PENDING, expiresAt: { gt: new Date() } }, select: { id: true, email: true, role: true, expiresAt: true, createdAt: true }, orderBy: { createdAt: 'desc' } }),
    ]);
    return { family, seats: { used: members.length, limit: family.seatLimit }, members, pendingInvites: invites };
  });

  app.delete('/api/families/:familyId/invites/:inviteId', { preHandler: auth }, async (request, reply) => {
    const { familyId, inviteId } = request.params as { familyId: string; inviteId: string };
    const member = await membership(request, reply, familyId); if (!member) return;
    if (member.role !== FamilyRole.OWNER) return fail(reply, 403, 'ROLE_FORBIDDEN');
    const result = await prisma.invite.updateMany({ where: { id: inviteId, familyId, status: InviteStatus.PENDING }, data: { status: InviteStatus.REVOKED, revokedAt: new Date() } });
    if (result.count !== 1) return fail(reply, 404, 'INVITE_NOT_FOUND');
    await audit(request.userId!, 'family.invite.cancelled', familyId, 'invite', inviteId, request.id);
    return reply.code(204).send();
  });

  app.delete('/api/families/:familyId/members/:userId', { preHandler: auth }, async (request, reply) => {
    const { familyId, userId } = request.params as { familyId: string; userId: string };
    const member = await membership(request, reply, familyId); if (!member) return;
    if (member.role !== FamilyRole.OWNER) return fail(reply, 403, 'ROLE_FORBIDDEN');
    const [family, target] = await Promise.all([
      prisma.family.findUniqueOrThrow({ where: { id: familyId }, select: { ownerId: true } }),
      prisma.familyMember.findUnique({ where: { userId }, select: { id: true, familyId: true, role: true } }),
    ]);
    if (!target || target.familyId !== familyId) return fail(reply, 404, 'MEMBER_NOT_FOUND');
    if (userId === family.ownerId || target.role === FamilyRole.OWNER) return fail(reply, 409, 'OWNER_CANNOT_BE_REMOVED');
    await prisma.$transaction(async tx => {
      await tx.familyMember.delete({ where: { id: target.id } });
      await tx.auditEvent.create({ data: { actorId: request.userId!, action: 'family.member.removed', familyId, subjectType: 'user', subjectId: userId, requestId: request.id } });
    });
    return reply.code(204).send();
  });

  app.post('/api/family-invites/accept', { preHandler: auth, config: { rateLimit: { max: 10, timeWindow: '15 minutes' } } }, async (request, reply) => {
    const { code } = inviteCodeInput.parse(request.body);
    try {
      const result = await prisma.$transaction(tx => acceptInviteInTransaction(tx, request.userId!, code, request.id));
      return { familyId: result.familyId, access: { granted: true } };
    } catch (error) {
      if (error instanceof FamilyInviteError) return fail(reply, error.code === 'ACTIVE_FAMILY_REQUIRED' ? 402 : error.code === 'SEATS_FULL' || error.code === 'ALREADY_IN_FAMILY' ? 409 : 400, error.code);
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') return fail(reply, 409, 'ALREADY_IN_FAMILY');
      throw error;
    }
  });

  app.post('/api/auth/invitations/accept', { config: { rateLimit: { max: 10, timeWindow: '15 minutes' } } }, async (request, reply) => {
    const input = z.object({ token: z.string().min(32).max(128), password: z.string().min(12).max(128), displayName: z.string().trim().min(1).max(120) }).strict().parse(request.body);
    const invitation = await prisma.invite.findUnique({ where: { codeHash: digest(input.token, config.INVITATION_HASH_KEY) } });
    if (!invitation || !invitation.email || invitation.status !== InviteStatus.PENDING || invitation.expiresAt <= new Date()) return fail(reply, 400, 'INVITATION_INVALID');
    const inviteeEmail = invitation.email.toLowerCase();
    if (await prisma.user.findUnique({ where: { email: inviteeEmail }, select: { id: true } })) return fail(reply, 409, 'ACCOUNT_ALREADY_EXISTS');
    const passwordHash = await argon2.hash(input.password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
    const sessionToken = newToken();
    let result: { user: ReturnType<typeof safeUser>; familyId: string };
    try {
      result = await prisma.$transaction(async tx => {
        const user = await tx.user.create({ data: { email: inviteeEmail, displayName: input.displayName, passwordHash }, select: { id: true, email: true, displayName: true } });
        const accepted = await acceptInviteInTransaction(tx, user.id, input.token, request.id);
        await tx.session.create({ data: { tokenHash: digest(sessionToken), userId: user.id, expiresAt: new Date(Date.now() + config.SESSION_TTL_DAYS * 86400000) } });
        await tx.auditEvent.create({ data: { actorId: user.id, action: 'auth.register', familyId: accepted.familyId, subjectType: 'user', subjectId: user.id, requestId: request.id } });
        return { user: safeUser(user), familyId: accepted.familyId };
      });
    } catch (error) {
      if (error instanceof FamilyInviteError) return fail(reply, error.code === 'ACTIVE_FAMILY_REQUIRED' ? 402 : error.code === 'SEATS_FULL' ? 409 : 400, error.code);
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') return fail(reply, 409, 'ACCOUNT_ALREADY_EXISTS');
      throw error;
    }
    setSessionCookie(reply, sessionToken);
    return { user: result.user, familyId: result.familyId };
  });

  const paypalCredentials = (): PayPalCredentials | null => config.PAYPAL_CLIENT_ID && config.PAYPAL_CLIENT_SECRET
    ? { clientId: config.PAYPAL_CLIENT_ID, clientSecret: config.PAYPAL_CLIENT_SECRET }
    : null;
  const paypalBillingConfigured = () => Boolean(
    paypalCredentials() && config.PAYPAL_WEBHOOK_ID && config.PAYPAL_CURRENCY &&
    config.PAYPAL_FAMILY_BASE_AMOUNT && config.PAYPAL_EXTRA_SEAT_AMOUNT && config.API_PUBLIC_URL
  );
  const appBillingRedirect = (reply: FastifyReply, status: 'success' | 'cancelled' | 'failed' | 'processing') => {
    const target = new URL(config.PUBLIC_APP_URL);
    target.searchParams.set('billing', status);
    return reply.code(303).header('location', target.toString()).send();
  };

  const applyCompletedPayPalOrder = async (tx: Prisma.TransactionClient, untrustedOrder: PayPalOrder): Promise<boolean> => {
    const order = asRecord(untrustedOrder);
    const orderId = textValue(order?.id);
    const purchaseUnits = Array.isArray(order?.purchase_units) ? order.purchase_units : [];
    const unit = asRecord(purchaseUnits[0]);
    const purchaseId = textValue(unit?.reference_id) ?? textValue(unit?.custom_id);
    const orderAmount = asRecord(unit?.amount);
    const payments = asRecord(unit?.payments);
    const captures = Array.isArray(payments?.captures) ? payments.captures : [];
    const capture = captures.map(asRecord).find(item => item?.status === 'COMPLETED') ?? null;
    const captureId = textValue(capture?.id);
    const captureAmount = asRecord(capture?.amount);
    if (!orderId || !purchaseId || !captureId || order?.status !== 'COMPLETED') return false;
    if (!config.PAYPAL_CURRENCY || !config.PAYPAL_FAMILY_BASE_AMOUNT || !config.PAYPAL_EXTRA_SEAT_AMOUNT) return false;
    if (textValue(orderAmount?.currency_code) !== config.PAYPAL_CURRENCY ||
        textValue(captureAmount?.currency_code) !== config.PAYPAL_CURRENCY) return false;

    await tx.$queryRaw<Array<{ id: string }>>`SELECT "id" FROM "billing_purchases" WHERE "id" = ${purchaseId} FOR UPDATE`;
    const purchase = await tx.billingPurchase.findUnique({ where: { id: purchaseId } });
    if (!purchase || purchase.provider !== BillingProvider.PAYPAL ||
        purchase.providerOrderId !== orderId) return false;
    const unitPrice = purchase.type === PurchaseType.FAMILY_BASE ? config.PAYPAL_FAMILY_BASE_AMOUNT : config.PAYPAL_EXTRA_SEAT_AMOUNT;
    const expectedAmount = amountForQuantity(unitPrice, purchase.type === PurchaseType.FAMILY_BASE ? 1 : purchase.seatQuantity);
    if (textValue(orderAmount?.value) !== expectedAmount || textValue(captureAmount?.value) !== expectedAmount) return false;
    if (purchase.status === PurchaseStatus.COMPLETED) return purchase.providerPaymentId === captureId;
    if (purchase.status !== PurchaseStatus.PENDING) return false;

    if (purchase.type === PurchaseType.FAMILY_BASE) {
      let family = await tx.family.findUnique({ where: { ownerId: purchase.userId } });
      if (family?.status === FamilyStatus.ACTIVE) {
        await tx.billingPurchase.update({ where: { id: purchase.id }, data: { status: PurchaseStatus.FAILED, baseCheckoutOwnerId: null, providerPaymentId: captureId } });
        return false;
      }
      const user = await tx.user.findUniqueOrThrow({ where: { id: purchase.userId }, select: { displayName: true } });
      const priorMembership = await tx.familyMember.findUnique({ where: { userId: purchase.userId } });
      if (priorMembership && (!family || priorMembership.familyId !== family.id)) {
        await tx.billingPurchase.update({ where: { id: purchase.id }, data: { status: PurchaseStatus.FAILED, baseCheckoutOwnerId: null, providerPaymentId: captureId } });
        return false;
      }
      if (!family) {
        family = await tx.family.create({
          data: {
            name: `${user.displayName}'s family`,
            ownerId: purchase.userId,
            seatLimit: 4,
            status: FamilyStatus.ACTIVE,
            memberships: { create: { userId: purchase.userId, role: FamilyRole.OWNER } },
          },
        });
      } else {
        const paidExtraSeats = await tx.billingPurchase.aggregate({
          where: { familyId: family.id, type: PurchaseType.EXTRA_SEATS, status: PurchaseStatus.COMPLETED },
          _sum: { seatQuantity: true },
        });
        family = await tx.family.update({
          where: { id: family.id },
          data: { status: FamilyStatus.ACTIVE, seatLimit: 4 + (paidExtraSeats._sum.seatQuantity ?? 0) },
        });
        if (priorMembership) await tx.familyMember.update({ where: { id: priorMembership.id }, data: { role: FamilyRole.OWNER } });
        else await tx.familyMember.create({ data: { familyId: family.id, userId: purchase.userId, role: FamilyRole.OWNER } });
      }
      await tx.billingPurchase.update({
        where: { id: purchase.id },
        data: { status: PurchaseStatus.COMPLETED, familyId: family.id, baseCheckoutOwnerId: null, providerPaymentId: captureId },
      });
      await tx.auditEvent.create({ data: { actorId: purchase.userId, action: 'billing.family.activated', familyId: family.id, subjectType: 'billing_purchase', subjectId: purchase.id } });
      return true;
    }

    if (!purchase.familyId) return false;
    const family = await tx.family.findUnique({ where: { id: purchase.familyId }, select: { id: true, ownerId: true, status: true } });
    if (!family || family.ownerId !== purchase.userId || family.status !== FamilyStatus.ACTIVE) {
      await tx.billingPurchase.update({ where: { id: purchase.id }, data: { status: PurchaseStatus.FAILED, providerPaymentId: captureId } });
      return false;
    }
    await tx.family.update({ where: { id: family.id }, data: { seatLimit: { increment: purchase.seatQuantity } } });
    await tx.billingPurchase.update({ where: { id: purchase.id }, data: { status: PurchaseStatus.COMPLETED, providerPaymentId: captureId } });
    await tx.auditEvent.create({ data: { actorId: purchase.userId, action: 'billing.family.seats_added', familyId: family.id, subjectType: 'billing_purchase', subjectId: purchase.id } });
    return true;
  };

  const processPayPalWebhook = async (event: PayPalWebhookEvent, order?: PayPalOrder, refundCaptureId?: string, refundOrderId?: string) => {
    try {
      await prisma.$transaction(async tx => {
        if (await tx.billingWebhookEvent.findUnique({ where: { id: event.id }, select: { id: true } })) return;
        await tx.billingWebhookEvent.create({ data: { id: event.id, provider: BillingProvider.PAYPAL, eventType: event.event_type } });
        if (order) await applyCompletedPayPalOrder(tx, order);
        if (refundCaptureId || refundOrderId) {
          const purchase = await tx.billingPurchase.findFirst({
            where: { OR: [
              ...(refundCaptureId ? [{ providerPaymentId: refundCaptureId }] : []),
              ...(refundOrderId ? [{ providerOrderId: refundOrderId }] : []),
            ] },
          });
          if (!purchase) return;
          await tx.billingPurchase.update({ where: { id: purchase.id }, data: { status: PurchaseStatus.REFUNDED, baseCheckoutOwnerId: null } });
          if (purchase.familyId) await tx.family.updateMany({ where: { id: purchase.familyId }, data: { status: FamilyStatus.INACTIVE } });
          await tx.auditEvent.create({ data: { actorId: null, action: 'billing.family.refunded', ...(purchase.familyId ? { familyId: purchase.familyId } : {}), subjectType: 'billing_purchase', subjectId: purchase.id } });
        }
      });
      return true;
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002' &&
          await prisma.billingWebhookEvent.findUnique({ where: { id: event.id }, select: { id: true } })) return false;
      throw error;
    }
  };

  app.post('/api/billing/family/base-checkout', { preHandler: auth, config: { rateLimit: { max: 5, timeWindow: '1 hour' } } }, async (request, reply) => {
    if (!paypalBillingConfigured()) return fail(reply, 503, 'BILLING_NOT_CONFIGURED');
    const credentials = paypalCredentials()!;
    const existingMembership = await prisma.familyMember.findUnique({ where: { userId: request.userId! }, include: { family: { select: { id: true, ownerId: true, status: true } } } });
    if (existingMembership && (existingMembership.role !== FamilyRole.OWNER || existingMembership.family.ownerId !== request.userId)) return fail(reply, 409, 'ALREADY_IN_FAMILY');
    if (existingMembership?.family.status === FamilyStatus.ACTIVE) return fail(reply, 409, 'FAMILY_ALREADY_ACTIVE');
    const ownedFamily = await prisma.family.findUnique({ where: { ownerId: request.userId! }, select: { id: true, status: true } });
    if (ownedFamily?.status === FamilyStatus.ACTIVE) return fail(reply, 409, 'FAMILY_ALREADY_ACTIVE');

    const now = new Date();
    let purchase = await prisma.billingPurchase.findFirst({
      where: { baseCheckoutOwnerId: request.userId!, status: PurchaseStatus.PENDING, provider: BillingProvider.PAYPAL },
      orderBy: { createdAt: 'desc' },
    });
    if (purchase?.checkoutExpiresAt && purchase.checkoutExpiresAt <= now) {
      await prisma.billingPurchase.update({ where: { id: purchase.id }, data: { status: PurchaseStatus.EXPIRED, baseCheckoutOwnerId: null } });
      purchase = null;
    }
    if (purchase?.checkoutUrl && purchase.checkoutExpiresAt && purchase.checkoutExpiresAt > now) {
      return { checkoutUrl: purchase.checkoutUrl, purchaseId: purchase.id, reused: true };
    }
    if (!purchase) {
      try {
        purchase = await prisma.billingPurchase.create({
          data: {
            type: PurchaseType.FAMILY_BASE,
            status: PurchaseStatus.PENDING,
            provider: BillingProvider.PAYPAL,
            userId: request.userId!,
            familyId: ownedFamily?.id ?? null,
            seatQuantity: 4,
            baseCheckoutOwnerId: request.userId!,
          },
        });
      } catch (error) {
        if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
          const concurrent = await prisma.billingPurchase.findFirst({
            where: { baseCheckoutOwnerId: request.userId!, status: PurchaseStatus.PENDING, provider: BillingProvider.PAYPAL },
          });
          if (concurrent?.checkoutUrl) return { checkoutUrl: concurrent.checkoutUrl, purchaseId: concurrent.id, reused: true };
          return fail(reply, 409, 'CHECKOUT_PENDING');
        }
        throw error;
      }
    }

    try {
      const order = await createPayPalOrder({
        credentials,
        purchaseId: purchase.id,
        description: 'CareCircle family plan',
        amount: amountForQuantity(config.PAYPAL_FAMILY_BASE_AMOUNT!, 1),
        currency: config.PAYPAL_CURRENCY!,
        returnUrl: `${config.API_PUBLIC_URL!.replace(/\/+$/, '')}/api/billing/paypal/return`,
        cancelUrl: `${config.API_PUBLIC_URL!.replace(/\/+$/, '')}/api/billing/paypal/cancel`,
      });
      const checkoutExpiresAt = new Date(Date.now() + 3 * 60 * 60 * 1000);
      await prisma.billingPurchase.update({
        where: { id: purchase.id },
        data: { providerOrderId: order.id, checkoutUrl: order.url, checkoutExpiresAt },
      });
      return { checkoutUrl: order.url, purchaseId: purchase.id, reused: false };
    } catch (error) {
      request.log.error({ requestId: request.id, errorName: error instanceof Error ? error.name : 'unknown', paypalStatus: error instanceof PayPalRequestError ? error.status : undefined }, 'family PayPal order creation failed');
      if (error instanceof PayPalRequestError && error.status !== null && error.status >= 400 && error.status < 500) {
        await prisma.billingPurchase.updateMany({ where: { id: purchase.id, status: PurchaseStatus.PENDING }, data: { status: PurchaseStatus.FAILED, baseCheckoutOwnerId: null } });
      }
      return fail(reply, 503, 'PAYMENT_PROVIDER_UNAVAILABLE');
    }
  });

  app.post('/api/families/:familyId/billing/extra-seats-checkout', { preHandler: auth, config: { rateLimit: { max: 10, timeWindow: '1 hour' } } }, async (request, reply) => {
    if (!paypalBillingConfigured()) return fail(reply, 503, 'BILLING_NOT_CONFIGURED');
    const credentials = paypalCredentials()!;
    const { familyId } = request.params as { familyId: string };
    const member = await membership(request, reply, familyId); if (!member) return;
    if (member.role !== FamilyRole.OWNER) return fail(reply, 403, 'ROLE_FORBIDDEN');
    const { quantity } = extraSeatsInput.parse(request.body);
    const family = await prisma.family.findUniqueOrThrow({ where: { id: familyId }, select: { ownerId: true, seatLimit: true } });
    if (family.ownerId !== request.userId) return fail(reply, 403, 'ROLE_FORBIDDEN');
    let purchase;
    try {
      purchase = await prisma.billingPurchase.create({
        data: { type: PurchaseType.EXTRA_SEATS, status: PurchaseStatus.PENDING, provider: BillingProvider.PAYPAL, userId: request.userId!, familyId, seatQuantity: quantity },
      });
    } catch (error) {
      request.log.error({ requestId: request.id, errorName: error instanceof Error ? error.name : 'unknown' }, 'extra seat purchase creation failed');
      return fail(reply, 503, 'PAYMENT_ORDER_UNAVAILABLE');
    }
    try {
      const order = await createPayPalOrder({
        credentials,
        purchaseId: purchase.id,
        description: `CareCircle extra family seats (${quantity})`,
        amount: amountForQuantity(config.PAYPAL_EXTRA_SEAT_AMOUNT!, quantity),
        currency: config.PAYPAL_CURRENCY!,
        returnUrl: `${config.API_PUBLIC_URL!.replace(/\/+$/, '')}/api/billing/paypal/return`,
        cancelUrl: `${config.API_PUBLIC_URL!.replace(/\/+$/, '')}/api/billing/paypal/cancel`,
      });
      const checkoutExpiresAt = new Date(Date.now() + 3 * 60 * 60 * 1000);
      await prisma.billingPurchase.update({
        where: { id: purchase.id },
        data: { providerOrderId: order.id, checkoutUrl: order.url, checkoutExpiresAt },
      });
      return { checkoutUrl: order.url, purchaseId: purchase.id, quantity };
    } catch (error) {
      request.log.error({ requestId: request.id, errorName: error instanceof Error ? error.name : 'unknown', paypalStatus: error instanceof PayPalRequestError ? error.status : undefined }, 'extra seat PayPal order creation failed');
      if (error instanceof PayPalRequestError && error.status !== null && error.status >= 400 && error.status < 500) {
        await prisma.billingPurchase.updateMany({ where: { id: purchase.id, status: PurchaseStatus.PENDING }, data: { status: PurchaseStatus.FAILED } });
      }
      return fail(reply, 503, 'PAYMENT_PROVIDER_UNAVAILABLE');
    }
  });

  app.get('/api/billing/paypal/return', async (request, reply) => {
    if (!paypalBillingConfigured()) return appBillingRedirect(reply, 'processing');
    const query = z.object({ token: z.string().min(5).max(80) }).safeParse(request.query);
    if (!query.success) return appBillingRedirect(reply, 'failed');
    const purchase = await prisma.billingPurchase.findUnique({ where: { providerOrderId: query.data.token } });
    if (!purchase || purchase.provider !== BillingProvider.PAYPAL) return appBillingRedirect(reply, 'failed');
    if (purchase.status === PurchaseStatus.COMPLETED) return appBillingRedirect(reply, 'success');
    if (purchase.status !== PurchaseStatus.PENDING) return appBillingRedirect(reply, 'failed');

    let order: PayPalOrder;
    try {
      try { order = await capturePayPalOrder(paypalCredentials()!, query.data.token); }
      catch { order = await getPayPalOrder(paypalCredentials()!, query.data.token); }
      const applied = await prisma.$transaction(tx => applyCompletedPayPalOrder(tx, order));
      return appBillingRedirect(reply, applied ? 'success' : 'processing');
    } catch (error) {
      request.log.error({ requestId: request.id, errorName: error instanceof Error ? error.name : 'unknown', paypalStatus: error instanceof PayPalRequestError ? error.status : undefined }, 'PayPal return capture failed');
      return appBillingRedirect(reply, 'processing');
    }
  });

  app.get('/api/billing/paypal/cancel', async (_request, reply) => {
    // Keep the pending order available for retry; PayPal does not void an un-captured order here.
    return appBillingRedirect(reply, 'cancelled');
  });

  app.post('/api/billing/paypal/webhook', { config: { rateLimit: { max: 300, timeWindow: '1 minute' } } }, async (request, reply) => {
    if (!paypalBillingConfigured() || !config.PAYPAL_WEBHOOK_ID) return fail(reply, 503, 'BILLING_NOT_CONFIGURED');
    let event: PayPalWebhookEvent | null;
    try {
      event = await verifyPayPalWebhook(paypalCredentials()!, config.PAYPAL_WEBHOOK_ID, request.headers, request.body);
    } catch (error) {
      request.log.error({ requestId: request.id, errorName: error instanceof Error ? error.name : 'unknown', paypalStatus: error instanceof PayPalRequestError ? error.status : undefined }, 'PayPal webhook verification service failed');
      return fail(reply, 503, 'WEBHOOK_VERIFICATION_UNAVAILABLE');
    }
    if (!event) return fail(reply, 400, 'WEBHOOK_SIGNATURE_INVALID');

    let completedOrder: PayPalOrder | undefined;
    let refundCaptureId: string | undefined;
    let refundOrderId: string | undefined;
    const resource = event.resource;
    const related = asRecord(asRecord(resource.supplementary_data)?.related_ids);
    const credentials = paypalCredentials()!;
    try {
      if (event.event_type === 'CHECKOUT.ORDER.APPROVED') {
        const orderId = textValue(resource.id);
        if (orderId) {
          try { completedOrder = await capturePayPalOrder(credentials, orderId); }
          catch { completedOrder = await getPayPalOrder(credentials, orderId); }
        }
      } else if (event.event_type === 'PAYMENT.CAPTURE.COMPLETED') {
        const orderId = textValue(related?.order_id);
        if (orderId) completedOrder = await getPayPalOrder(credentials, orderId);
      } else if (event.event_type === 'PAYMENT.CAPTURE.REFUNDED' || event.event_type === 'PAYMENT.CAPTURE.REVERSED') {
        refundCaptureId = textValue(related?.capture_id) ?? textValue(resource.id) ?? undefined;
        refundOrderId = textValue(related?.order_id) ?? undefined;
      }
      await processPayPalWebhook(event, completedOrder, refundCaptureId, refundOrderId);
      return reply.code(204).send();
    } catch (error) {
      request.log.error({ requestId: request.id, eventId: event.id, eventType: event.event_type, errorName: error instanceof Error ? error.name : 'unknown', paypalStatus: error instanceof PayPalRequestError ? error.status : undefined }, 'PayPal webhook processing failed');
      return fail(reply, 503, 'WEBHOOK_PROCESSING_FAILED');
    }
  });

  app.get('/api/families/:familyId/records', { preHandler: auth }, async (request, reply) => {
    const { familyId } = request.params as { familyId: string };
    const member = await membership(request, reply, familyId); if (!member) return;
    const query = z.object({ kind: z.nativeEnum(RecordKind).optional(), limit: z.coerce.number().int().min(1).max(100).default(50), cursor: z.string().optional() }).parse(request.query);
    if (query.kind === RecordKind.HOUSEHOLD_INCOME && !isAdmin(member.role)) return fail(reply, 403, 'SENSITIVE_RECORD_FORBIDDEN');
    const where = { familyId, ...(query.kind ? { kind: query.kind } : isAdmin(member.role) ? {} : { kind: { not: RecordKind.HOUSEHOLD_INCOME } }) };
    const rows = await prisma.careRecord.findMany({ where, take: query.limit + 1, ...(query.cursor ? { skip: 1, cursor: { id: query.cursor } } : {}), orderBy: { createdAt: 'desc' } });
    return { items: rows.slice(0, query.limit), nextCursor: rows.length > query.limit ? rows[query.limit - 1]?.id : null };
  });

  app.post('/api/families/:familyId/records', { preHandler: auth }, async (request, reply) => {
    const { familyId } = request.params as { familyId: string };
    const member = await membership(request, reply, familyId); if (!member) return;
    if (member.role === FamilyRole.VIEWER) return fail(reply, 403, 'ROLE_FORBIDDEN');
    const input = recordInput.parse(request.body);
    if (!recordKinds.has(input.kind)) return fail(reply, 400, 'RECORD_KIND_INVALID');
    if (input.kind === RecordKind.HOUSEHOLD_INCOME && !isAdmin(member.role)) return fail(reply, 403, 'SENSITIVE_RECORD_FORBIDDEN');
    if (JSON.stringify(input.data).length > 12000) return fail(reply, 413, 'RECORD_TOO_LARGE');
    const record = await prisma.careRecord.create({ data: { ...input, data: input.data as Prisma.InputJsonValue, familyId, createdById: request.userId! } });
    await audit(request.userId!, `record.${input.kind.toLowerCase()}.created`, familyId, input.kind, record.id, request.id);
    return reply.code(201).send(record);
  });

  app.patch('/api/families/:familyId/records/:recordId', { preHandler: auth }, async (request, reply) => {
    const { familyId, recordId } = request.params as { familyId: string; recordId: string };
    const member = await membership(request, reply, familyId); if (!member) return;
    const existing = await prisma.careRecord.findFirst({ where: { id: recordId, familyId } });
    if (!existing) return fail(reply, 404, 'RECORD_NOT_FOUND');
    if (member.role === FamilyRole.VIEWER || (existing.kind === RecordKind.HOUSEHOLD_INCOME && !isAdmin(member.role))) return fail(reply, 403, 'ROLE_FORBIDDEN');
    const input = z.object({ title: z.string().trim().min(1).max(200).optional(), data: z.record(z.string(), z.unknown()).optional() }).strict().refine(v => Object.keys(v).length > 0).parse(request.body);
    if (input.data && JSON.stringify(input.data).length > 12000) return fail(reply, 413, 'RECORD_TOO_LARGE');
    const updated = await prisma.careRecord.update({ where: { id: recordId }, data: { ...(input.title === undefined ? {} : { title: input.title }), ...(input.data === undefined ? {} : { data: input.data as Prisma.InputJsonValue }) } });
    await audit(request.userId!, `record.${existing.kind.toLowerCase()}.updated`, familyId, existing.kind, recordId, request.id);
    return updated;
  });

  app.delete('/api/families/:familyId/records/:recordId', { preHandler: auth }, async (request, reply) => {
    const { familyId, recordId } = request.params as { familyId: string; recordId: string };
    const member = await membership(request, reply, familyId); if (!member) return;
    if (!isAdmin(member.role)) return fail(reply, 403, 'ROLE_FORBIDDEN');
    const existing = await prisma.careRecord.findFirst({ where: { id: recordId, familyId } });
    if (!existing) return fail(reply, 404, 'RECORD_NOT_FOUND');
    if (existing.kind === RecordKind.HOUSEHOLD_INCOME && member.role !== FamilyRole.OWNER) return fail(reply, 403, 'SENSITIVE_RECORD_FORBIDDEN');
    await prisma.careRecord.delete({ where: { id: recordId } });
    await audit(request.userId!, `record.${existing.kind.toLowerCase()}.deleted`, familyId, existing.kind, recordId, request.id);
    return reply.code(204).send();
  });

  app.addHook('onClose', async () => { await prisma.$disconnect(); if (redis) await redis.quit().catch(() => redis.disconnect()); });
  return app;
}

// Vercel detects src/app.ts before src/index.ts; expose the configured Fastify server.
export default await buildApp();
