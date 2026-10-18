import { defineConfig } from 'vitest/config';

process.env.NODE_ENV ??= 'test';
process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.APP_ORIGIN ??= 'http://localhost:5173';
process.env.PUBLIC_APP_URL ??= 'http://localhost:5173';
process.env.SESSION_HASH_KEY ??= 'test-session-key-please-replace-000000';
process.env.INVITATION_HASH_KEY ??= 'test-invitation-key-please-replace-00000';

export default defineConfig({ test: { environment: 'node' } });
