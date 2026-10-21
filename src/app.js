import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import * as oidc from 'openid-client';
import { randomBytes, timingSafeEqual } from 'node:crypto';

const save = req => new Promise((resolve, reject) => req.session.save(e => e ? reject(e) : resolve()));
const regenerate = req => new Promise((resolve, reject) => req.session.regenerate(e => e ? reject(e) : resolve()));

export function createApp({ configuration, baseUrl, sessionSecret, production = false, store }) {
  oidc.enableNonRepudiationChecks(configuration);
  const base = new URL(baseUrl);
  if (base.pathname !== '/' || base.search || base.hash || base.username || base.password) throw new Error('APP_URL must be an origin');
  if (production && (base.protocol !== 'https:' || !store)) throw new Error('Production requires HTTPS and a persistent session store');
  if (!sessionSecret || sessionSecret.length < 32) throw new Error('SESSION_SECRET must contain at least 32 characters');
  const app = express();
  app.disable('x-powered-by');
  // Deploy behind exactly one trusted reverse proxy in production.
  if (production) app.set('trust proxy', 1);
  app.use(helmet({ strictTransportSecurity: production ? undefined : false }));
  app.use(express.urlencoded({ extended: false, limit: '4kb' }));
  app.use(session({ name: 'auth.sid', secret: sessionSecret, resave: false, saveUninitialized: false,
    store, cookie: { httpOnly: true, secure: production, sameSite: 'lax', maxAge: 60 * 60 * 1000 } }));
  app.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  const loginLimit = rateLimit({ windowMs: 60_000, limit: 20 });
  app.get('/healthz', (req, res) => res.json({ status: 'ok' }));
  app.get('/', (req, res) => {
    req.session.csrf ??= randomBytes(32).toString('hex');
    res.type('html').send(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>用户认证</title><body><main><h1>用户认证</h1>${req.session.user ? `<p>登录成功。可通过 <a href="/api/me">用户信息接口</a> 查看认证信息。</p><form action="/logout" method="post"><input type="hidden" name="csrf" value="${req.session.csrf}"><button>退出登录</button></form>` : '<p>请通过认证服务安全登录。</p><a href="/login">登录</a>'}</main></body></html>`);
  });
  app.get('/login', loginLimit, async (req, res) => {
    const codeVerifier = oidc.randomPKCECodeVerifier();
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();
    req.session.pending = { codeVerifier, state, nonce, created: Date.now() };
    const url = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: new URL('/callback', base).href, scope: 'openid profile email',
      response_type: 'code', code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier),
      code_challenge_method: 'S256', state, nonce,
    });
    await save(req);
    res.redirect(url.href);
  });
  app.get('/callback', async (req, res) => {
    const pending = req.session.pending;
    delete req.session.pending;
    await save(req);
    if (!pending || Date.now() - pending.created > 5 * 60_000) return res.status(400).send('登录请求已失效，请重新登录。');
    try {
      const current = new URL(req.originalUrl, base);
      const tokens = await oidc.authorizationCodeGrant(configuration, current, {
        pkceCodeVerifier: pending.codeVerifier, expectedState: pending.state,
        expectedNonce: pending.nonce, idTokenExpected: true,
      });
      const claims = tokens.claims();
      // Return only validated identity claims. Tokens and credentials never reach the browser.
      const user = { sub: claims.sub, iss: claims.iss, name: claims.name, email: claims.email,
        email_verified: claims.email_verified };
      await regenerate(req);
      req.session.user = user;
      req.session.csrf = randomBytes(32).toString('hex');
      await save(req);
      res.redirect('/');
    } catch {
      res.status(400).send('认证失败，请重新登录。');
    }
  });
  app.get('/api/me', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'unauthenticated' });
    res.json({ user: req.session.user });
  });
  app.post('/logout', async (req, res, next) => {
    const expected = req.session.csrf;
    const actual = req.body.csrf;
    if (typeof actual !== 'string' || !expected || Buffer.byteLength(actual) !== Buffer.byteLength(expected) ||
      !timingSafeEqual(Buffer.from(actual), Buffer.from(expected))) return res.sendStatus(403);
    req.session.destroy(err => {
      if (err) return next(err);
      res.clearCookie('auth.sid', { httpOnly: true, secure: production, sameSite: 'lax' });
      res.redirect('/');
    });
  });
  app.use((err, req, res, next) => {
    // Avoid logging provider errors, URLs, credentials, or token responses.
    res.status(500).json({ error: 'authentication_service_error' });
  });
  return app;
}
