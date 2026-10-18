CREATE TYPE "BillingProvider" AS ENUM ('STRIPE', 'PAYPAL');

ALTER TABLE "billing_purchases"
  ADD COLUMN "provider" "BillingProvider" NOT NULL DEFAULT 'STRIPE',
  ADD COLUMN "provider_order_id" VARCHAR(255),
  ADD COLUMN "provider_payment_id" VARCHAR(255);

UPDATE "billing_purchases"
SET "provider_order_id" = "stripeCheckoutSessionId",
    "provider_payment_id" = "stripePaymentIntentId";

-- Existing open Stripe checkouts are no longer actionable. Preserve completed
-- Stripe purchases and their provider IDs for historical reconciliation.
UPDATE "billing_purchases"
SET "status" = 'FAILED',
    "baseCheckoutOwnerId" = NULL,
    "checkoutUrl" = NULL,
    "checkoutExpiresAt" = NULL
WHERE "provider" = 'STRIPE' AND "status" = 'PENDING';

ALTER TABLE "billing_purchases"
  DROP COLUMN "stripeCheckoutSessionId",
  DROP COLUMN "stripePaymentIntentId",
  ALTER COLUMN "provider" SET DEFAULT 'PAYPAL';

CREATE UNIQUE INDEX "billing_purchases_provider_order_id_key"
  ON "billing_purchases"("provider_order_id");
CREATE UNIQUE INDEX "billing_purchases_provider_payment_id_key"
  ON "billing_purchases"("provider_payment_id");

ALTER TABLE "stripe_webhook_events"
  ADD COLUMN "provider" "BillingProvider" NOT NULL DEFAULT 'STRIPE';
ALTER TABLE "stripe_webhook_events" RENAME TO "billing_webhook_events";
ALTER TABLE "billing_webhook_events"
  RENAME CONSTRAINT "stripe_webhook_events_pkey" TO "billing_webhook_events_pkey",
  ALTER COLUMN "provider" SET DEFAULT 'PAYPAL';
ALTER INDEX "stripe_webhook_events_createdAt_idx"
  RENAME TO "billing_webhook_events_createdAt_idx";
