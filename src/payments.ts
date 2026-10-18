import { createHash } from 'node:crypto';

export class PayPalRequestError extends Error {
  constructor(readonly status: number | null, message = 'PayPal request failed') {
    super(message);
    this.name = 'PayPalRequestError';
  }
}

export type PayPalCredentials = { clientId: string; clientSecret: string };
export type PayPalOrder = Record<string, unknown>;
export type PayPalWebhookEvent = { id: string; event_type: string; resource: Record<string, unknown> };
type HeaderBag = Record<string, string | string[] | undefined>;

const PAYPAL_API = 'https://api-m.sandbox.paypal.com';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function idempotencyKey(action: string, value: string): string {
  const digest = createHash('sha256').update(value).digest('hex').slice(0, 24);
  return `cc-${action}-${digest}`;
}

async function getAccessToken(credentials: PayPalCredentials): Promise<string> {
  let response: Response;
  try {
    response = await fetch(`${PAYPAL_API}/v1/oauth2/token`, {
      method: 'POST',
      headers: {
        authorization: `Basic ${Buffer.from(`${credentials.clientId}:${credentials.clientSecret}`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ grant_type: 'client_credentials' }),
      signal: AbortSignal.timeout(10000),
    });
  } catch {
    throw new PayPalRequestError(null);
  }
  if (!response.ok) throw new PayPalRequestError(response.status);
  let payload: unknown;
  try { payload = await response.json() as unknown; }
  catch { throw new PayPalRequestError(response.status); }
  if (!isRecord(payload) || typeof payload.access_token !== 'string' || payload.access_token.length < 20) {
    throw new PayPalRequestError(502);
  }
  return payload.access_token;
}

async function paypalRequest<T>(credentials: PayPalCredentials, path: string, init: RequestInit = {}): Promise<T> {
  const token = await getAccessToken(credentials);
  let response: Response;
  try {
    response = await fetch(`${PAYPAL_API}${path}`, {
      ...init,
      headers: {
        authorization: `Bearer ${token}`,
        ...(init.headers ?? {}),
      },
      signal: init.signal ?? AbortSignal.timeout(10000),
    });
  } catch {
    throw new PayPalRequestError(null);
  }
  if (!response.ok) throw new PayPalRequestError(response.status);
  if (response.status === 204) return undefined as T;
  try { return await response.json() as T; }
  catch { throw new PayPalRequestError(response.status); }
}

export async function createPayPalOrder(input: {
  credentials: PayPalCredentials;
  purchaseId: string;
  description: string;
  amount: string;
  currency: string;
  returnUrl: string;
  cancelUrl: string;
}): Promise<{ id: string; url: string }> {
  if (!/^[A-Z]{3}$/.test(input.currency) || !/^(?:0|[1-9]\d{0,8})\.\d{2}$/.test(input.amount) || Number(input.amount) <= 0) {
    throw new PayPalRequestError(400);
  }
  const order = await paypalRequest<PayPalOrder>(input.credentials, '/v2/checkout/orders', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'PayPal-Request-Id': idempotencyKey('create', input.purchaseId),
      prefer: 'return=representation',
    },
    body: JSON.stringify({
      intent: 'CAPTURE',
      purchase_units: [{
        reference_id: input.purchaseId,
        custom_id: input.purchaseId,
        invoice_id: input.purchaseId.slice(0, 127),
        description: input.description.slice(0, 127),
        amount: { currency_code: input.currency, value: input.amount },
      }],
      application_context: {
        brand_name: 'CareCircle',
        user_action: 'PAY_NOW',
        return_url: input.returnUrl,
        cancel_url: input.cancelUrl,
      },
    }),
  });
  const links = Array.isArray(order.links) ? order.links : [];
  const approval = links.find(value => isRecord(value) && (value.rel === 'payer-action' || value.rel === 'approve'));
  if (typeof order.id !== 'string' || !isRecord(approval) || typeof approval.href !== 'string') {
    throw new PayPalRequestError(502);
  }
  return { id: order.id, url: approval.href };
}

export async function capturePayPalOrder(credentials: PayPalCredentials, orderId: string): Promise<PayPalOrder> {
  if (!/^[A-Za-z0-9-]{5,80}$/.test(orderId)) throw new PayPalRequestError(400);
  return paypalRequest<PayPalOrder>(credentials, `/v2/checkout/orders/${encodeURIComponent(orderId)}/capture`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'PayPal-Request-Id': idempotencyKey('capture', orderId),
      prefer: 'return=representation',
    },
    body: '{}',
  });
}

export async function getPayPalOrder(credentials: PayPalCredentials, orderId: string): Promise<PayPalOrder> {
  if (!/^[A-Za-z0-9-]{5,80}$/.test(orderId)) throw new PayPalRequestError(400);
  return paypalRequest<PayPalOrder>(credentials, `/v2/checkout/orders/${encodeURIComponent(orderId)}`);
}

function header(headers: HeaderBag, name: string): string | null {
  const value = headers[name.toLowerCase()];
  return typeof value === 'string' ? value : null;
}

export async function verifyPayPalWebhook(
  credentials: PayPalCredentials,
  webhookId: string,
  headers: HeaderBag,
  untrustedEvent: unknown,
): Promise<PayPalWebhookEvent | null> {
  if (!isRecord(untrustedEvent) || typeof untrustedEvent.id !== 'string' ||
      typeof untrustedEvent.event_type !== 'string' || !isRecord(untrustedEvent.resource)) return null;

  const authAlgo = header(headers, 'paypal-auth-algo');
  const certUrl = header(headers, 'paypal-cert-url');
  const transmissionId = header(headers, 'paypal-transmission-id');
  const transmissionSig = header(headers, 'paypal-transmission-sig');
  const transmissionTime = header(headers, 'paypal-transmission-time');
  if (!authAlgo || !certUrl || !transmissionId || !transmissionSig || !transmissionTime) return null;
  try {
    const certificate = new URL(certUrl);
    if (certificate.protocol !== 'https:' ||
        !['api-m.sandbox.paypal.com', 'api.sandbox.paypal.com'].includes(certificate.hostname)) return null;
  } catch { return null; }

  const verification = await paypalRequest<Record<string, unknown>>(credentials, '/v1/notifications/verify-webhook-signature', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      auth_algo: authAlgo,
      cert_url: certUrl,
      transmission_id: transmissionId,
      transmission_sig: transmissionSig,
      transmission_time: transmissionTime,
      webhook_id: webhookId,
      webhook_event: untrustedEvent,
    }),
  });
  if (verification.verification_status !== 'SUCCESS') return null;
  return untrustedEvent as PayPalWebhookEvent;
}
