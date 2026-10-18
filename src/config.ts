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
  PAYPAL_CLIENT_ID: optionalString,
  PAYPAL_CLIENT_SECRET: optionalString,
  PAYPAL_WEBHOOK_ID: optionalString,
  PAYPAL_CURRENCY: z.preprocess(value => value === '' ? undefined : value, z.string().regex(/^[A-Za-z]{3}$/).transform(value => value.toUpperCase()).optional()),
  PAYPAL_FAMILY_BASE_AMOUNT: z.preprocess(value => value === '' ? undefined : value, z.string().regex(/^\d{1,8}(?:\.\d{1,2})?$/).optional()),
  PAYPAL_EXTRA_SEAT_AMOUNT: z.preprocess(value => value === '' ? undefined : value, z.string().regex(/^\d{1,8}(?:\.\d{1,2})?$/).optional()),
  API_PUBLIC_URL: optionalUrl,
  APP_ORIGIN: z.string().url(),
  PUBLIC_APP_URL: z.string().url(),
  SESSION_COOKIE_NAME: z.string().default('cc_session'),
  SESSION_TTL_DAYS: z.coerce.number().int().min(1).max(30).default(14),
  SESSION_HASH_KEY: z.string().min(32),
  INVITATION_HASH_KEY: z.string().min(32),
}).superRefine((value, ctx) => {
  if (value.NODE_ENV === 'production' && !value.REDIS_URL) ctx.addIssue({ code: 'custom', path: ['REDIS_URL'], message: 'REDIS_URL is required in production for shared rate limits' });
  // Billing remains disabled until a complete PayPal sandbox configuration is supplied.
  const paypalValues = [value.PAYPAL_CLIENT_ID, value.PAYPAL_CLIENT_SECRET, value.PAYPAL_WEBHOOK_ID, value.PAYPAL_CURRENCY, value.PAYPAL_FAMILY_BASE_AMOUNT, value.PAYPAL_EXTRA_SEAT_AMOUNT, value.API_PUBLIC_URL];
  if (paypalValues.some(Boolean) && paypalValues.some(item => !item)) ctx.addIssue({ code: 'custom', path: ['PAYPAL_CLIENT_ID'], message: 'Configure all PayPal sandbox values together or leave billing unconfigured' });
  for (const key of ['PAYPAL_FAMILY_BASE_AMOUNT', 'PAYPAL_EXTRA_SEAT_AMOUNT'] as const) {
    if (value[key] && (Number(value[key]) <= 0 || Number(value[key]) > 1000000)) ctx.addIssue({ code: 'custom', path: [key], message: `${key} must be greater than zero and at most 1000000` });
  }
  if (value.NODE_ENV === 'production' && value.APP_ORIGIN.startsWith('https://') === false) ctx.addIssue({ code: 'custom', path: ['APP_ORIGIN'], message: 'Production browser origin must use HTTPS' });
  if (value.NODE_ENV === 'production' && value.PUBLIC_APP_URL.startsWith('https://') === false) ctx.addIssue({ code: 'custom', path: ['PUBLIC_APP_URL'], message: 'Production app URL must use HTTPS' });
  if (value.NODE_ENV === 'production' && value.API_PUBLIC_URL && !value.API_PUBLIC_URL.startsWith('https://')) ctx.addIssue({ code: 'custom', path: ['API_PUBLIC_URL'], message: 'Production API URL must use HTTPS' });
  if (value.SESSION_HASH_KEY === value.INVITATION_HASH_KEY) ctx.addIssue({ code: 'custom', path: ['INVITATION_HASH_KEY'], message: 'Session and invitation hash keys must be distinct' });
  if (value.NODE_ENV === 'production' && (value.SESSION_HASH_KEY.includes('replace-with') || value.INVITATION_HASH_KEY.includes('replace-with'))) ctx.addIssue({ code: 'custom', path: ['SESSION_HASH_KEY'], message: 'Replace example hash keys with random environment secrets' });
});

export const config = schema.parse(process.env);
export const isProduction = config.NODE_ENV === 'production';
