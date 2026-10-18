import { createHmac, timingSafeEqual } from 'node:crypto';

export class StripeRequestError extends Error {
  constructor(readonly status: number | null, message = 'Stripe request failed') {
    super(message);
    this.name = 'StripeRequestError';
  }
}

export type StripeEvent = {
  id: string;
  type: string;
  data: { object: Record<string, unknown> };
};

export type CheckoutInput = {
  secretKey: string;
  priceId: string;
  quantity: number;
  purchaseId: string;
  purchaseType: 'FAMILY_BASE' | 'EXTRA_SEATS';
  ownerUserId: string;
  familyId?: string;
  successUrl: string;
  cancelUrl: string;
};

export type CheckoutResult = { id: string; url: string; expiresAt: Date };

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function verifyStripeSignature(rawBody: Buffer, signatureHeader: string, secret: string, nowMs = Date.now()): StripeEvent {
  const parts = signatureHeader.split(',').map(part => part.trim().split('=', 2));
  const timestamp = parts.find(([key]) => key === 't')?.[1];
  const signatures = parts.filter(([key]) => key === 'v1').map(([, value]) => value).filter((value): value is string => typeof value === 'string');
  if (!timestamp || !/^\d+$/.test(timestamp) || signatures.length === 0) throw new Error('Invalid Stripe signature header');
  const seconds = Number(timestamp);
  if (!Number.isSafeInteger(seconds) || Math.abs(Math.floor(nowMs / 1000) - seconds) > 300) throw new Error('Stale Stripe signature');

  const expected = createHmac('sha256', secret).update(Buffer.concat([Buffer.from(`${timestamp}.`, 'utf8'), rawBody])).digest();
  const valid = signatures.some(signature => {
    if (!/^[a-f0-9]{64}$/i.test(signature)) return false;
    const provided = Buffer.from(signature, 'hex');
    return provided.length === expected.length && timingSafeEqual(provided, expected);
  });
  if (!valid) throw new Error('Invalid Stripe signature');

  let decoded: unknown;
  try { decoded = JSON.parse(rawBody.toString('utf8')) as unknown; }
  catch { throw new Error('Invalid Stripe event JSON'); }
  if (!isObject(decoded) || typeof decoded.id !== 'string' || typeof decoded.type !== 'string' || !isObject(decoded.data) || !isObject(decoded.data.object)) {
    throw new Error('Invalid Stripe event structure');
  }
  return decoded as StripeEvent;
}

async function stripeRequest<T>(secretKey: string, path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`https://api.stripe.com/v1/${path}`, {
      ...init,
      headers: {
        authorization: `Bearer ${secretKey}`,
        ...(init?.headers ?? {}),
      },
      signal: init?.signal ?? AbortSignal.timeout(10000),
    });
  } catch {
    throw new StripeRequestError(null);
  }
  if (!response.ok) {
    // Provider error bodies can include account details; don't propagate or log them.
    throw new StripeRequestError(response.status);
  }
  try { return await response.json() as T; }
  catch { throw new StripeRequestError(response.status); }
}

export async function createCheckoutSession(input: CheckoutInput): Promise<CheckoutResult> {
  const body = new URLSearchParams();
  body.set('mode', 'payment');
  body.set('line_items[0][price]', input.priceId);
  body.set('line_items[0][quantity]', String(input.quantity));
  body.set('success_url', input.successUrl);
  body.set('cancel_url', input.cancelUrl);
  body.set('client_reference_id', input.purchaseId);
  body.set('metadata[purchaseId]', input.purchaseId);
  body.set('metadata[purchaseType]', input.purchaseType);
  body.set('metadata[ownerUserId]', input.ownerUserId);
  body.set('payment_intent_data[metadata][purchaseId]', input.purchaseId);
  body.set('payment_intent_data[metadata][purchaseType]', input.purchaseType);
  body.set('payment_intent_data[metadata][ownerUserId]', input.ownerUserId);
  if (input.familyId) {
    body.set('metadata[familyId]', input.familyId);
    body.set('payment_intent_data[metadata][familyId]', input.familyId);
  }

  const session = await stripeRequest<{ id?: unknown; url?: unknown; expires_at?: unknown }>(input.secretKey, 'checkout/sessions', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'idempotency-key': `carecircle-purchase-${input.purchaseId}` },
    body,
  });
  if (typeof session.id !== 'string' || typeof session.url !== 'string' || typeof session.expires_at !== 'number') {
    throw new StripeRequestError(502);
  }
  return { id: session.id, url: session.url, expiresAt: new Date(session.expires_at * 1000) };
}

export async function retrievePaymentIntentMetadata(secretKey: string, paymentIntentId: string): Promise<Record<string, string>> {
  if (!/^pi_[A-Za-z0-9]+$/.test(paymentIntentId)) throw new StripeRequestError(400);
  const intent = await stripeRequest<{ metadata?: unknown }>(secretKey, `payment_intents/${encodeURIComponent(paymentIntentId)}`);
  if (!isObject(intent.metadata)) return {};
  return Object.fromEntries(Object.entries(intent.metadata).filter((entry): entry is [string, string] => typeof entry[1] === 'string'));
}
