import * as oidc from 'openid-client';
import { createApp } from './app.js';
import { createClient } from 'redis';
import { RedisStore } from 'connect-redis';

for (const key of ['OIDC_ISSUER', 'OIDC_CLIENT_ID', 'SESSION_SECRET', 'APP_URL']) {
  if (!process.env[key]) throw new Error(`Missing environment variable: ${key}`);
}
const issuer = new URL(process.env.OIDC_ISSUER);
if (issuer.protocol !== 'https:') throw new Error('OIDC_ISSUER must use HTTPS');
const configuration = await oidc.discovery(issuer, process.env.OIDC_CLIENT_ID, process.env.OIDC_CLIENT_SECRET);
const production = process.env.NODE_ENV === 'production';
let store;
if (production || process.env.REDIS_URL) {
  if (!process.env.REDIS_URL) throw new Error('Production requires REDIS_URL');
  const redis = createClient({ url: process.env.REDIS_URL });
  redis.on('error', () => console.error('Session store unavailable'));
  await redis.connect();
  store = new RedisStore({ client: redis, prefix: 'auth-web:' });
}
const app = createApp({ configuration, baseUrl: process.env.APP_URL,
  sessionSecret: process.env.SESSION_SECRET, production, store });
app.listen(Number(process.env.PORT || 3000), '0.0.0.0', () => console.log('Authentication web server started'));
