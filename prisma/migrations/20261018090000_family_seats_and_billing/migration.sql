CREATE TYPE "FamilyStatus" AS ENUM ('ACTIVE', 'INACTIVE');
CREATE TYPE "InviteStatus" AS ENUM ('PENDING', 'ACCEPTED', 'REVOKED', 'EXPIRED');
CREATE TYPE "PurchaseType" AS ENUM ('FAMILY_BASE', 'EXTRA_SEATS');
CREATE TYPE "PurchaseStatus" AS ENUM ('PENDING', 'COMPLETED', 'EXPIRED', 'FAILED', 'REFUNDED');

ALTER TABLE "Family" RENAME TO "families";
ALTER TABLE "Membership" RENAME TO "family_members";
ALTER TABLE "Invitation" RENAME TO "invites";
ALTER TABLE "family_members" RENAME COLUMN "familyId" TO "family_id";
ALTER TABLE "family_members" RENAME COLUMN "userId" TO "user_id";
ALTER TABLE "invites" RENAME COLUMN "familyId" TO "family_id";
ALTER TABLE "invites" RENAME COLUMN "tokenHash" TO "code_hash";
ALTER TABLE "invites" RENAME COLUMN "expiresAt" TO "expires_at";
ALTER TABLE "invites" ALTER COLUMN "email" DROP NOT NULL;

ALTER TABLE "families"
  ADD COLUMN "owner_id" TEXT,
  ADD COLUMN "seat_limit" INTEGER NOT NULL DEFAULT 4,
  ADD COLUMN "status" "FamilyStatus" NOT NULL DEFAULT 'INACTIVE';
ALTER TABLE "families" ADD CONSTRAINT "families_seat_limit_check" CHECK ("seat_limit" >= 1);

-- Older prototype data allowed one account in multiple workspaces. Preserve the
-- displaced membership rows for auditability, then enforce one family per user.
CREATE TABLE "family_member_legacy_archive" (
  "id" TEXT PRIMARY KEY,
  "familyId" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "role" "FamilyRole" NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL,
  "archivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
WITH ranked AS (
  SELECT "id", "family_id" AS "familyId", "user_id" AS "userId", "role", "createdAt",
    ROW_NUMBER() OVER (
      PARTITION BY "user_id"
      ORDER BY CASE WHEN "role" = 'OWNER' THEN 0 ELSE 1 END, "createdAt", "id"
    ) AS position
  FROM "family_members"
)
INSERT INTO "family_member_legacy_archive" ("id", "familyId", "userId", "role", "createdAt")
SELECT "id", "familyId", "userId", "role", "createdAt" FROM ranked WHERE position > 1;
WITH ranked AS (
  SELECT "id", ROW_NUMBER() OVER (
    PARTITION BY "user_id"
    ORDER BY CASE WHEN "role" = 'OWNER' THEN 0 ELSE 1 END, "createdAt", "id"
  ) AS position
  FROM "family_members"
)
DELETE FROM "family_members" AS member USING ranked
WHERE member."id" = ranked."id" AND ranked.position > 1;

UPDATE "families" AS family
SET "owner_id" = candidate."userId"
FROM (
  SELECT DISTINCT ON ("family_id") "family_id" AS "familyId", "user_id" AS "userId"
  FROM "family_members"
  ORDER BY "family_id", CASE WHEN "role" = 'OWNER' THEN 0 ELSE 1 END, "createdAt", "id"
) AS candidate
WHERE candidate."familyId" = family."id";
UPDATE "family_members" AS member
SET "role" = 'OWNER'
WHERE member."id" IN (
  SELECT DISTINCT ON ("family_id") "id"
  FROM "family_members"
  ORDER BY "family_id", CASE WHEN "role" = 'OWNER' THEN 0 ELSE 1 END, "createdAt", "id"
);

ALTER TABLE "invites"
  ADD COLUMN "status" "InviteStatus" NOT NULL DEFAULT 'PENDING';
UPDATE "invites"
SET "status" = CASE
  WHEN "acceptedAt" IS NOT NULL THEN 'ACCEPTED'::"InviteStatus"
  WHEN "revokedAt" IS NOT NULL THEN 'REVOKED'::"InviteStatus"
  WHEN "expires_at" <= CURRENT_TIMESTAMP THEN 'EXPIRED'::"InviteStatus"
  ELSE 'PENDING'::"InviteStatus"
END;

ALTER TABLE "families" RENAME CONSTRAINT "Family_pkey" TO "families_pkey";
ALTER TABLE "family_members" RENAME CONSTRAINT "Membership_pkey" TO "family_members_pkey";
ALTER TABLE "invites" RENAME CONSTRAINT "Invitation_pkey" TO "invites_pkey";
ALTER TABLE "family_members" RENAME CONSTRAINT "Membership_familyId_fkey" TO "family_members_family_id_fkey";
ALTER TABLE "family_members" RENAME CONSTRAINT "Membership_userId_fkey" TO "family_members_user_id_fkey";
ALTER TABLE "invites" RENAME CONSTRAINT "Invitation_familyId_fkey" TO "invites_family_id_fkey";
ALTER TABLE "invites" RENAME CONSTRAINT "Invitation_createdById_fkey" TO "invites_createdById_fkey";
ALTER INDEX "Membership_familyId_userId_key" RENAME TO "family_members_family_id_user_id_key";
ALTER INDEX "Invitation_tokenHash_key" RENAME TO "invites_code_hash_key";
DROP INDEX "Membership_userId_idx";
DROP INDEX "Invitation_familyId_email_idx";
ALTER INDEX "Invitation_expiresAt_idx" RENAME TO "invites_expires_at_idx";

CREATE UNIQUE INDEX "families_owner_id_key" ON "families"("owner_id");
CREATE INDEX "families_status_idx" ON "families"("status");
CREATE UNIQUE INDEX "family_members_user_id_key" ON "family_members"("user_id");
CREATE INDEX "invites_family_id_status_expires_at_idx" ON "invites"("family_id", "status", "expires_at");

CREATE TABLE "billing_purchases" (
  "id" TEXT NOT NULL,
  "type" "PurchaseType" NOT NULL,
  "status" "PurchaseStatus" NOT NULL DEFAULT 'PENDING',
  "userId" TEXT NOT NULL,
  "familyId" TEXT,
  "seatQuantity" INTEGER NOT NULL,
  "baseCheckoutOwnerId" TEXT,
  "stripeCheckoutSessionId" VARCHAR(255),
  "stripePaymentIntentId" VARCHAR(255),
  "checkoutUrl" TEXT,
  "checkoutExpiresAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "billing_purchases_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "billing_purchases_seatQuantity_check" CHECK ("seatQuantity" >= 1)
);
CREATE UNIQUE INDEX "billing_purchases_baseCheckoutOwnerId_key" ON "billing_purchases"("baseCheckoutOwnerId");
CREATE UNIQUE INDEX "billing_purchases_stripeCheckoutSessionId_key" ON "billing_purchases"("stripeCheckoutSessionId");
CREATE UNIQUE INDEX "billing_purchases_stripePaymentIntentId_key" ON "billing_purchases"("stripePaymentIntentId");
CREATE INDEX "billing_purchases_userId_createdAt_idx" ON "billing_purchases"("userId", "createdAt");
CREATE INDEX "billing_purchases_familyId_status_idx" ON "billing_purchases"("familyId", "status");
ALTER TABLE "billing_purchases" ADD CONSTRAINT "billing_purchases_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "billing_purchases" ADD CONSTRAINT "billing_purchases_familyId_fkey"
  FOREIGN KEY ("familyId") REFERENCES "families"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "families" ADD CONSTRAINT "families_owner_id_fkey"
  FOREIGN KEY ("owner_id") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE TABLE "stripe_webhook_events" (
  "id" VARCHAR(255) NOT NULL,
  "eventType" VARCHAR(120) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "stripe_webhook_events_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "stripe_webhook_events_createdAt_idx" ON "stripe_webhook_events"("createdAt");
