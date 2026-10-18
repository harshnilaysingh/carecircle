CREATE TYPE "FamilyStatus" AS ENUM ('ACTIVE', 'INACTIVE');
CREATE TYPE "InviteStatus" AS ENUM ('PENDING', 'ACCEPTED', 'REVOKED', 'EXPIRED');
CREATE TYPE "PurchaseType" AS ENUM ('FAMILY_BASE', 'EXTRA_SEATS');
CREATE TYPE "PurchaseStatus" AS ENUM ('PENDING', 'COMPLETED', 'EXPIRED', 'FAILED', 'REFUNDED');

ALTER TABLE "Family" RENAME TO "families";
ALTER TABLE "Membership" RENAME TO "family_members";
ALTER TABLE "Invitation" RENAME TO "invites";
ALTER TABLE "invites" RENAME COLUMN "tokenHash" TO "codeHash";
ALTER TABLE "invites" ALTER COLUMN "email" DROP NOT NULL;

ALTER TABLE "families"
  ADD COLUMN "ownerId" TEXT,
  ADD COLUMN "seatLimit" INTEGER NOT NULL DEFAULT 4,
  ADD COLUMN "status" "FamilyStatus" NOT NULL DEFAULT 'INACTIVE';
ALTER TABLE "families" ADD CONSTRAINT "families_seatLimit_check" CHECK ("seatLimit" >= 1);

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
  SELECT "id", "familyId", "userId", "role", "createdAt",
    ROW_NUMBER() OVER (
      PARTITION BY "userId"
      ORDER BY CASE WHEN "role" = 'OWNER' THEN 0 ELSE 1 END, "createdAt", "id"
    ) AS position
  FROM "family_members"
)
INSERT INTO "family_member_legacy_archive" ("id", "familyId", "userId", "role", "createdAt")
SELECT "id", "familyId", "userId", "role", "createdAt" FROM ranked WHERE position > 1;
WITH ranked AS (
  SELECT "id", ROW_NUMBER() OVER (
    PARTITION BY "userId"
    ORDER BY CASE WHEN "role" = 'OWNER' THEN 0 ELSE 1 END, "createdAt", "id"
  ) AS position
  FROM "family_members"
)
DELETE FROM "family_members" AS member USING ranked
WHERE member."id" = ranked."id" AND ranked.position > 1;

UPDATE "families" AS family
SET "ownerId" = candidate."userId"
FROM (
  SELECT DISTINCT ON ("familyId") "familyId", "userId"
  FROM "family_members"
  ORDER BY "familyId", CASE WHEN "role" = 'OWNER' THEN 0 ELSE 1 END, "createdAt", "id"
) AS candidate
WHERE candidate."familyId" = family."id";
UPDATE "family_members" AS member
SET "role" = 'OWNER'
WHERE member."id" IN (
  SELECT DISTINCT ON ("familyId") "id"
  FROM "family_members"
  ORDER BY "familyId", CASE WHEN "role" = 'OWNER' THEN 0 ELSE 1 END, "createdAt", "id"
);

ALTER TABLE "invites"
  ADD COLUMN "status" "InviteStatus" NOT NULL DEFAULT 'PENDING';
UPDATE "invites"
SET "status" = CASE
  WHEN "acceptedAt" IS NOT NULL THEN 'ACCEPTED'::"InviteStatus"
  WHEN "revokedAt" IS NOT NULL THEN 'REVOKED'::"InviteStatus"
  WHEN "expiresAt" <= CURRENT_TIMESTAMP THEN 'EXPIRED'::"InviteStatus"
  ELSE 'PENDING'::"InviteStatus"
END;

ALTER TABLE "families" RENAME CONSTRAINT "Family_pkey" TO "families_pkey";
ALTER TABLE "family_members" RENAME CONSTRAINT "Membership_pkey" TO "family_members_pkey";
ALTER TABLE "invites" RENAME CONSTRAINT "Invitation_pkey" TO "invites_pkey";
ALTER TABLE "family_members" RENAME CONSTRAINT "Membership_familyId_fkey" TO "family_members_familyId_fkey";
ALTER TABLE "family_members" RENAME CONSTRAINT "Membership_userId_fkey" TO "family_members_userId_fkey";
ALTER TABLE "invites" RENAME CONSTRAINT "Invitation_familyId_fkey" TO "invites_familyId_fkey";
ALTER TABLE "invites" RENAME CONSTRAINT "Invitation_createdById_fkey" TO "invites_createdById_fkey";
ALTER INDEX "Membership_familyId_userId_key" RENAME TO "family_members_familyId_userId_key";
ALTER INDEX "Invitation_tokenHash_key" RENAME TO "invites_codeHash_key";
DROP INDEX "Membership_userId_idx";
DROP INDEX "Invitation_familyId_email_idx";
ALTER INDEX "Invitation_expiresAt_idx" RENAME TO "invites_expiresAt_idx";

CREATE UNIQUE INDEX "families_ownerId_key" ON "families"("ownerId");
CREATE INDEX "families_status_idx" ON "families"("status");
CREATE UNIQUE INDEX "family_members_userId_key" ON "family_members"("userId");
CREATE INDEX "invites_familyId_status_expiresAt_idx" ON "invites"("familyId", "status", "expiresAt");

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
ALTER TABLE "families" ADD CONSTRAINT "families_ownerId_fkey"
  FOREIGN KEY ("ownerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE TABLE "stripe_webhook_events" (
  "id" VARCHAR(255) NOT NULL,
  "eventType" VARCHAR(120) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "stripe_webhook_events_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "stripe_webhook_events_createdAt_idx" ON "stripe_webhook_events"("createdAt");
