import { buildApp } from './app.js';
import { config } from './config.js';

const app = await buildApp();
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => { void app.close().finally(() => process.exit(0)); });
}
try { await app.listen({ host: config.HOST, port: config.PORT }); }
catch (error) { app.log.fatal({ err: error }, 'server startup failed'); await app.close(); process.exit(1); }
