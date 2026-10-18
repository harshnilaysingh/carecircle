import { z } from 'zod';

const optionalString = z.preprocess(value => value === '' ? undefined : value, z.string().min(1).optional());
const optionalUrl = z.preprocess(value => value === '' ? undefined : value, z.string().url().optional());

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3001),
  HOST: z.string().default('0.0.0.0'),
  TRUST_PROXY: z.enum(['true', 'false']).default('false').transform(value => value === 'true'),
  DATABASE_URL: z.string().min(1),
  REDIS_URL: optionalUrl,
  RESEND_API_KEY: optionalString,
  EMAIL_FROM: z.string().email().max(320).optional(),
  STRIPE_SECRET_KEY: optionalString,
  STRIPE_WEBHOOK_SECRET: optionalString,
  STRIPE_BASE_PRICE_ID: optionalString,
  STRIPE_EXTRA_SEAT_PRICE_ID: optionalString,
  STRIPE_SUCCESS_URL: optionalUrl,
  STRIPE_CANCEL_URL: optionalUrl,
  APP_ORIGIN: z.string().url(),
  PUBLIC_APP_URL: z.string().url(),
  SESSION_COOKIE_NAME: z.string().default('cc_session'),
  SESSION_TTL_DAYS: z.coerce.number().int().min(1).max(30).default(14),
  SESSION_HASH_KEY: z.string().min(32),
  INVITATION_HASH_KEY: z.string().min(32),
}).superRefine((value, ctx) => {
  if (value.NODE_ENV === 'production' && !value.REDIS_URL) ctx.addIssue({ code: 'custom', path: ['REDIS_URL'], message: 'REDIS_URL is required in production for shared rate limits' });
  if (value.NODE_ENV === 'production' && !value.RESEND_API_KEY) ctx.addIssue({ code: 'custom', path: ['RESEND_API_KEY'], message: 'RESEND_API_KEY is required in production to deliver invitations' });
  if (value.NODE_ENV === 'production' && !value.EMAIL_FROM) ctx.addIssue({ code: 'custom', path: ['EMAIL_FROM'], message: 'EMAIL_FROM is required in production to deliver invitations' });
  for (const key of ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'STRIPE_BASE_PRICE_ID', 'STRIPE_EXTRA_SEAT_PRICE_ID'] as const) {
    if (value.NODE_ENV === 'production' && !value[key]) ctx.addIssue({ code: 'custom', path: [key], message: `${key} is required in production for family billing` });
    if (value.NODE_ENV === 'production' && value[key]?.toLowerCase().includes('replace')) ctx.addIssue({ code: 'custom', path: [key], message: `${key} must be a real Stripe production value` });
  }
  if (value.NODE_ENV === 'production' && value.STRIPE_SECRET_KEY && !/^(sk_live_|rk_live_)/.test(value.STRIPE_SECRET_KEY)) ctx.addIssue({ code: 'custom', path: ['STRIPE_SECRET_KEY'], message: 'Production Stripe key must use live mode' });
  if (value.NODE_ENV === 'production' && value.STRIPE_WEBHOOK_SECRET && !value.STRIPE_WEBHOOK_SECRET.startsWith('whsec_')) ctx.addIssue({ code: 'custom', path: ['STRIPE_WEBHOOK_SECRET'], message: 'Stripe webhook signing secret must be valid' });
  if (value.NODE_ENV === 'production' && value.STRIPE_BASE_PRICE_ID && !value.STRIPE_BASE_PRICE_ID.startsWith('price_')) ctx.addIssue({ code: 'custom', path: ['STRIPE_BASE_PRICE_ID'], message: 'Stripe family price ID must be valid' });
  if (value.NODE_ENV === 'production' && value.STRIPE_EXTRA_SEAT_PRICE_ID && !value.STRIPE_EXTRA_SEAT_PRICE_ID.startsWith('price_')) ctx.addIssue({ code: 'custom', path: ['STRIPE_EXTRA_SEAT_PRICE_ID'], message: 'Stripe extra-seat price ID must be valid' });
  if (value.NODE_ENV === 'production' && value.STRIPE_SUCCESS_URL && !value.STRIPE_SUCCESS_URL.startsWith('https://')) ctx.addIssue({ code: 'custom', path: ['STRIPE_SUCCESS_URL'], message: 'Production checkout success URL must use HTTPS' });
  if (value.NODE_ENV === 'production' && value.STRIPE_CANCEL_URL && !value.STRIPE_CANCEL_URL.startsWith('https://')) ctx.addIssue({ code: 'custom', path: ['STRIPE_CANCEL_URL'], message: 'Production checkout cancel URL must use HTTPS' });
  if (value.NODE_ENV === 'production' && value.APP_ORIGIN.startsWith('https://') === false) ctx.addIssue({ code: 'custom', path: ['APP_ORIGIN'], message: 'Production browser origin must use HTTPS' });
  if (value.NODE_ENV === 'production' && value.PUBLIC_APP_URL.startsWith('https://') === false) ctx.addIssue({ code: 'custom', path: ['PUBLIC_APP_URL'], message: 'Production app URL must use HTTPS' });
  if (value.SESSION_HASH_KEY === value.INVITATION_HASH_KEY) ctx.addIssue({ code: 'custom', path: ['INVITATION_HASH_KEY'], message: 'Session and invitation hash keys must be distinct' });
  if (value.NODE_ENV === 'production' && (value.SESSION_HASH_KEY.includes('replace-with') || value.INVITATION_HASH_KEY.includes('replace-with'))) ctx.addIssue({ code: 'custom', path: ['SESSION_HASH_KEY'], message: 'Replace example hash keys with random environment secrets' });
});

export const config = schema.parse(process.env);
export const isProduction = config.NODE_ENV === 'production';
