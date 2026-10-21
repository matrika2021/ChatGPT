import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import request from 'supertest';
import * as oidc from 'openid-client';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createHash } from 'node:crypto';
import { createApp } from '../src/app.js';

test('OIDC login validates state, nonce, PKCE and signature; session and logout work', async t => {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = { ...await exportJWK(publicKey), kid: 'test-key', alg: 'RS256', use: 'sig' };
  let nonce, challenge, issuer, invalidNonce = false, invalidSignature = false;
  const wrongKey = await generateKeyPair('RS256');
  const provider = express();
  provider.use(express.urlencoded({ extended: false }));
  provider.get('/.well-known/openid-configuration', (req, res) => res.json({
    issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`, response_types_supported: ['code'], subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'], token_endpoint_auth_methods_supported: ['none'],
  }));
  provider.get('/jwks', (req, res) => res.json({ keys: [jwk] }));
  provider.post('/token', async (req, res) => {
    assert.equal(req.body.redirect_uri, 'http://localhost:3000/callback');
    assert.equal(req.body.code, 'valid-code');
    assert.equal(createHash('sha256').update(req.body.code_verifier).digest('base64url'), challenge);
    const idToken = await new SignJWT({ nonce: invalidNonce ? 'wrong' : nonce, name: '测试用户', email: 'test@example.com' })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' }).setIssuer(issuer).setAudience('test-client')
      .setSubject('user-123').setIssuedAt().setExpirationTime('5m').sign(invalidSignature ? wrongKey.privateKey : privateKey);
    res.json({ access_token: 'must-not-leak', token_type: 'Bearer', id_token: idToken });
  });
  const server = provider.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  issuer = `http://127.0.0.1:${server.address().port}`;
  const configuration = await oidc.discovery(new URL(issuer), 'test-client', undefined, oidc.None(), { execute: [oidc.allowInsecureRequests] });
  const agent = request.agent(createApp({ configuration, baseUrl: 'http://localhost:3000', sessionSecret: 'a'.repeat(64) }));
  await agent.get('/healthz').expect(200, { status: 'ok' });
  await agent.get('/api/me').expect(401);
  await agent.get('/callback?code=valid-code&state=forged').expect(400);
  const login = async () => {
    const response = await agent.get('/login').expect(302);
    const url = new URL(response.headers.location);
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    nonce = url.searchParams.get('nonce'); challenge = url.searchParams.get('code_challenge');
    return url.searchParams.get('state');
  };
  await login();
  await agent.get('/callback?code=valid-code&state=forged').expect(400);
  await agent.get('/api/me').expect(401);
  let state = await login(); invalidNonce = true;
  await agent.get(`/callback?code=valid-code&state=${state}`).expect(400);
  await agent.get('/api/me').expect(401);
  state = await login(); invalidNonce = false; invalidSignature = true;
  await agent.get(`/callback?code=valid-code&state=${state}`).expect(400);
  await agent.get('/api/me').expect(401);
  state = await login(); invalidSignature = false;
  await agent.get(`/callback?code=valid-code&state=${state}`).expect(302).expect('Location', '/');
  const me = await agent.get('/api/me').expect(200);
  assert.equal(me.body.user.sub, 'user-123');
  assert.equal(me.body.user.iss, issuer);
  assert.ok(!JSON.stringify(me.body).includes('must-not-leak'));
  await agent.get(`/callback?code=valid-code&state=${state}`).expect(400);
  await agent.post('/logout').type('form').send({ csrf: 'forged' }).expect(403);
  const page = await agent.get('/').expect(200);
  const csrf = page.text.match(/name="csrf" value="([a-f0-9]+)"/)[1];
  await agent.post('/logout').type('form').send({ csrf }).expect(302);
  await agent.get('/api/me').expect(401);
});
