CREATE TYPE "FamilyRole" AS ENUM ('OWNER', 'ADMIN', 'CAREGIVER', 'VIEWER');
CREATE TYPE "RecordKind" AS ENUM ('TASK', 'DAILY_UPDATE', 'CHAT_MESSAGE', 'APPOINTMENT', 'PROFILE', 'CARE_INFORMATION', 'HOUSEHOLD_INCOME');

CREATE TABLE "User" (
  "id" TEXT NOT NULL, "email" VARCHAR(320) NOT NULL, "passwordHash" VARCHAR(255) NOT NULL,
  "displayName" VARCHAR(120) NOT NULL, "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL, CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "Session" (
  "id" TEXT NOT NULL, "tokenHash" CHAR(64) NOT NULL, "userId" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL, "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "Family" (
  "id" TEXT NOT NULL, "name" VARCHAR(120) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP, "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "Family_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "Membership" (
  "id" TEXT NOT NULL, "familyId" TEXT NOT NULL, "userId" TEXT NOT NULL,
  "role" "FamilyRole" NOT NULL DEFAULT 'CAREGIVER', "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "Membership_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "Invitation" (
  "id" TEXT NOT NULL, "familyId" TEXT NOT NULL, "email" VARCHAR(320) NOT NULL,
  "role" "FamilyRole" NOT NULL, "tokenHash" CHAR(64) NOT NULL, "expiresAt" TIMESTAMP(3) NOT NULL,
  "acceptedAt" TIMESTAMP(3), "revokedAt" TIMESTAMP(3), "createdById" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "Invitation_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "CareRecord" (
  "id" TEXT NOT NULL, "familyId" TEXT NOT NULL, "kind" "RecordKind" NOT NULL,
  "title" VARCHAR(200) NOT NULL, "data" JSONB NOT NULL, "createdById" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP, "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "CareRecord_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "AuditEvent" (
  "id" TEXT NOT NULL, "familyId" TEXT, "actorId" TEXT, "action" VARCHAR(100) NOT NULL,
  "subjectType" VARCHAR(80), "subjectId" VARCHAR(100), "requestId" VARCHAR(100),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "AuditEvent_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
CREATE UNIQUE INDEX "Session_tokenHash_key" ON "Session"("tokenHash");
CREATE INDEX "Session_userId_expiresAt_idx" ON "Session"("userId", "expiresAt");
CREATE INDEX "Session_expiresAt_idx" ON "Session"("expiresAt");
CREATE UNIQUE INDEX "Membership_familyId_userId_key" ON "Membership"("familyId", "userId");
CREATE INDEX "Membership_userId_idx" ON "Membership"("userId");
CREATE UNIQUE INDEX "Invitation_tokenHash_key" ON "Invitation"("tokenHash");
CREATE INDEX "Invitation_familyId_email_idx" ON "Invitation"("familyId", "email");
CREATE INDEX "Invitation_expiresAt_idx" ON "Invitation"("expiresAt");
CREATE INDEX "CareRecord_familyId_kind_updatedAt_idx" ON "CareRecord"("familyId", "kind", "updatedAt");
CREATE INDEX "CareRecord_familyId_createdAt_idx" ON "CareRecord"("familyId", "createdAt");
CREATE INDEX "AuditEvent_familyId_createdAt_idx" ON "AuditEvent"("familyId", "createdAt");
CREATE INDEX "AuditEvent_actorId_createdAt_idx" ON "AuditEvent"("actorId", "createdAt");

ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Membership" ADD CONSTRAINT "Membership_familyId_fkey" FOREIGN KEY ("familyId") REFERENCES "Family"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Membership" ADD CONSTRAINT "Membership_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Invitation" ADD CONSTRAINT "Invitation_familyId_fkey" FOREIGN KEY ("familyId") REFERENCES "Family"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Invitation" ADD CONSTRAINT "Invitation_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "CareRecord" ADD CONSTRAINT "CareRecord_familyId_fkey" FOREIGN KEY ("familyId") REFERENCES "Family"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "CareRecord" ADD CONSTRAINT "CareRecord_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_familyId_fkey" FOREIGN KEY ("familyId") REFERENCES "Family"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
