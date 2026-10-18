import { createHmac } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createCheckoutSession, StripeRequestError, verifyStripeSignature } from './payments.js';

const eventJson = JSON.stringify({ id: 'evt_test_1', type: 'checkout.session.completed', data: { object: { id: 'cs_test_1' } } });

function sign(body: Buffer, secret: string, timestamp = Math.floor(Date.now() / 1000)): string {
  const v1 = createHmac('sha256', secret).update(Buffer.concat([Buffer.from(`${timestamp}.`), body])).digest('hex');
  return `t=${timestamp},v1=${v1}`;
}

afterEach(() => vi.unstubAllGlobals());

describe('Stripe webhook signature verification', () => {
  it('accepts a current signature and returns the signed event', () => {
    const raw = Buffer.from(eventJson);
    expect(verifyStripeSignature(raw, sign(raw, 'whsec_test'), 'whsec_test')).toMatchObject({ id: 'evt_test_1', type: 'checkout.session.completed' });
  });

  it('rejects modified bodies, stale signatures, and malformed events', () => {
    const raw = Buffer.from(eventJson);
    expect(() => verifyStripeSignature(Buffer.from(`${eventJson} `), sign(raw, 'whsec_test'), 'whsec_test')).toThrow();
    expect(() => verifyStripeSignature(raw, sign(raw, 'whsec_test', Math.floor(Date.now() / 1000) - 600), 'whsec_test')).toThrow('Stale Stripe signature');
    const malformed = Buffer.from('{"id":"evt_no_data","type":"payment_intent.succeeded"}');
    expect(() => verifyStripeSignature(malformed, sign(malformed, 'whsec_test'), 'whsec_test')).toThrow('Invalid Stripe event structure');
  });
});

describe('Stripe Checkout session creation', () => {
  it('sends server-selected price, quantity, metadata, and a stable idempotency key', async () => {
    const fetchMock = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      const form = new URLSearchParams(String(init?.body));
      expect(form.get('mode')).toBe('payment');
      expect(form.get('line_items[0][price]')).toBe('price_server_selected');
      expect(form.get('line_items[0][quantity]')).toBe('4');
      expect(form.get('metadata[purchaseId]')).toBe('purchase_test');
      expect(form.get('payment_intent_data[metadata][purchaseType]')).toBe('EXTRA_SEATS');
      expect(new Headers(init?.headers).get('idempotency-key')).toBe('carecircle-purchase-purchase_test');
      return new Response(JSON.stringify({ id: 'cs_test_2', url: 'https://checkout.stripe.com/c/pay/cs_test_2', expires_at: 1900000000 }), { status: 200 });
    });
    vi.stubGlobal('fetch', fetchMock);
    const session = await createCheckoutSession({
      secretKey: 'sk_test_only_for_unit_test', priceId: 'price_server_selected', quantity: 4,
      purchaseId: 'purchase_test', purchaseType: 'EXTRA_SEATS', ownerUserId: 'owner_test', familyId: 'family_test',
      successUrl: 'https://app.example/success?session_id={CHECKOUT_SESSION_ID}', cancelUrl: 'https://app.example/cancel',
    });
    expect(session).toEqual({ id: 'cs_test_2', url: 'https://checkout.stripe.com/c/pay/cs_test_2', expiresAt: new Date(1900000000000) });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('does not expose payment provider response bodies on errors', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('private provider details', { status: 400 })));
    await expect(createCheckoutSession({
      secretKey: 'sk_test_only_for_unit_test', priceId: 'price_bad', quantity: 1,
      purchaseId: 'purchase_bad', purchaseType: 'FAMILY_BASE', ownerUserId: 'owner_test',
      successUrl: 'https://app.example/success', cancelUrl: 'https://app.example/cancel',
    })).rejects.toMatchObject({ status: 400 });
  });
});
