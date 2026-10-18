import { afterEach, describe, expect, it, vi } from 'vitest';
import { capturePayPalOrder, createPayPalOrder, PayPalRequestError, verifyPayPalWebhook } from './payments.js';

const credentials = { clientId: 'sandbox-client-id', clientSecret: 'sandbox-client-secret' };

afterEach(() => vi.unstubAllGlobals());

describe('PayPal sandbox checkout', () => {
  it('creates a server-priced order with a stable idempotency key and approval URL', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/v1/oauth2/token')) return new Response(JSON.stringify({ access_token: 'sandbox-access-token-long-enough', expires_in: 300 }), { status: 200 });
      expect(url).toBe('https://api-m.sandbox.paypal.com/v2/checkout/orders');
      expect(new Headers(init?.headers).get('PayPal-Request-Id')).toMatch(/^cc-create-/);
      const body = JSON.parse(String(init?.body)) as { purchase_units: Array<{ reference_id: string; amount: { value: string; currency_code: string } }>; application_context: { return_url: string } };
      expect(body.purchase_units[0]).toMatchObject({ reference_id: 'purchase_test', amount: { value: '19.99', currency_code: 'USD' } });
      expect(body.application_context.return_url).toBe('https://api.example/api/billing/paypal/return');
      return new Response(JSON.stringify({ id: 'ORDER-TEST-12345', links: [{ rel: 'payer-action', href: 'https://www.sandbox.paypal.com/checkoutnow?token=ORDER-TEST-12345' }] }), { status: 201 });
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(createPayPalOrder({
      credentials, purchaseId: 'purchase_test', description: 'CareCircle family plan',
      amount: '19.99', currency: 'USD', returnUrl: 'https://api.example/api/billing/paypal/return',
      cancelUrl: 'https://api.example/api/billing/paypal/cancel',
    })).resolves.toEqual({ id: 'ORDER-TEST-12345', url: 'https://www.sandbox.paypal.com/checkoutnow?token=ORDER-TEST-12345' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('captures approved orders in sandbox with a retry-safe request id', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input).endsWith('/v1/oauth2/token')) return new Response(JSON.stringify({ access_token: 'sandbox-access-token-long-enough' }), { status: 200 });
      expect(String(input)).toBe('https://api-m.sandbox.paypal.com/v2/checkout/orders/ORDER-TEST-12345/capture');
      expect(new Headers(init?.headers).get('PayPal-Request-Id')).toMatch(/^cc-capture-/);
      return new Response(JSON.stringify({ id: 'ORDER-TEST-12345', status: 'COMPLETED' }), { status: 201 });
    });
    vi.stubGlobal('fetch', fetchMock);
    await expect(capturePayPalOrder(credentials, 'ORDER-TEST-12345')).resolves.toMatchObject({ id: 'ORDER-TEST-12345', status: 'COMPLETED' });
  });

  it('verifies webhook signatures with PayPal before accepting the event', async () => {
    const event = { id: 'WH-TEST-1', event_type: 'PAYMENT.CAPTURE.COMPLETED', resource: { id: 'CAPTURE-TEST-1' } };
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input).endsWith('/v1/oauth2/token')) return new Response(JSON.stringify({ access_token: 'sandbox-access-token-long-enough' }), { status: 200 });
      expect(String(input)).toBe('https://api-m.sandbox.paypal.com/v1/notifications/verify-webhook-signature');
      const body = JSON.parse(String(init?.body)) as { webhook_id: string; webhook_event: unknown };
      expect(body).toMatchObject({ webhook_id: 'webhook-test-id', webhook_event: event });
      return new Response(JSON.stringify({ verification_status: 'SUCCESS' }), { status: 200 });
    });
    vi.stubGlobal('fetch', fetchMock);
    const headers = {
      'paypal-auth-algo': 'SHA256withRSA',
      'paypal-cert-url': 'https://api-m.sandbox.paypal.com/v1/notifications/certs/test',
      'paypal-transmission-id': 'transmission-test',
      'paypal-transmission-sig': 'signature-test',
      'paypal-transmission-time': '2026-10-18T00:00:00Z',
    };
    await expect(verifyPayPalWebhook(credentials, 'webhook-test-id', headers, event)).resolves.toEqual(event);
  });

  it('rejects untrusted webhook certificate URLs and hides provider error bodies', async () => {
    const fetchMock = vi.fn(async () => new Response('private provider details', { status: 400 }));
    vi.stubGlobal('fetch', fetchMock);
    const event = { id: 'WH-TEST-2', event_type: 'PAYMENT.CAPTURE.COMPLETED', resource: { id: 'CAPTURE-TEST-2' } };
    const headers = {
      'paypal-auth-algo': 'SHA256withRSA',
      'paypal-cert-url': 'https://evil.example/cert',
      'paypal-transmission-id': 'transmission-test',
      'paypal-transmission-sig': 'signature-test',
      'paypal-transmission-time': '2026-10-18T00:00:00Z',
    };
    await expect(verifyPayPalWebhook(credentials, 'webhook-test-id', headers, event)).resolves.toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
    await expect(createPayPalOrder({
      credentials, purchaseId: 'purchase_bad', description: 'family', amount: '0.00',
      currency: 'USD', returnUrl: 'https://api.example/return', cancelUrl: 'https://api.example/cancel',
    })).rejects.toBeInstanceOf(PayPalRequestError);
  });
});
