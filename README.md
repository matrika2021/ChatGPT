# 认证 Web 服务

Node.js 24 + Express + openid-client，实现 OIDC Authorization Code + PKCE 登录。

## 启动

```sh
cd /workspace/auth-web
npm ci --cache /tmp/auth-npm-cache
cp .env.example .env
# 在 .env 中填写实际配置，切勿提交密钥。
# 可用 node -e "console.log(require('crypto').randomBytes(48).toString('hex'))" 生成 SESSION_SECRET。
npm start
```

在认证服务中注册一个 Web 客户端，启用 Authorization Code，回调地址精确注册为
`http://localhost:3000/callback`。默认使用 client_secret_post；公共客户端可将
OIDC_CLIENT_SECRET 留空。配置 HTTPS 的 OIDC_ISSUER（包括 realm/tenant 路径）、
OIDC_CLIENT_ID 和至少 32 字符的 SESSION_SECRET。
APP_URL 是此 Web 服务对外的源地址，不能包含路径。修改它时同步修改注册回调地址。

打开首页点击登录，浏览器跳转至认证服务，认证服务负责收集密码/MFA。
回调后服务端交换并验证 ID Token，将验证后的身份信息存入会话。
`GET /api/me` 返回当前浏览器会话的用户信息，未登录返回 401；令牌不会返回给浏览器。
`GET /healthz` 是进程健康检查，不代表认证服务或 Redis 可用。
`POST /logout` 带首页提供的 CSRF 字段销毁本地会话，不注销认证服务上的 SSO 会话。
当前会话最长一小时；不实现令牌刷新或实时同步认证服务上的账号撤销。

## 生产部署

设置 `NODE_ENV=production`、HTTPS 的 APP_URL 和 REDIS_URL。
通过 Redis 保存服务端会话，生产模式禁止默认内存存储。安装依赖后启动 Redis
并将其地址通过环境变量传入；认证数据应限制访问，远程 Redis 应使用 TLS。
只支持前方恰好一个可信反向代理，代理需覆盖 X-Forwarded-* 请求头，
应用端口应仅允许代理访问。否则需调整 trust proxy 后再部署。
内存会话与 HTTP APP_URL 仅用于本机开发；开发环境重启会丢失会话。

## 认证角色与后续对接

本项目是 OIDC 客户端（Relying Party），不是签发令牌的认证服务器。
标准流程是认证服务器把授权码交给本服务，再由本服务交换令牌并建立登录状态。
如果另一个业务服务器需要接收用户认证结果，应在明确其接口、鉴权与信任关系后，
增加服务端集成或将业务服务器注册为独立 OIDC 客户端。
本项目没有把密码、令牌或浏览器提交的身份字段转发给任意服务器的接口。

## 验证

```sh
npm test
```

测试启动独立的本地模拟 OIDC 服务，执行 discovery、JWKS 签名验证、
授权码交换、PKCE 校验、state/nonce 拒绝、会话查询和 CSRF 退出登录。
仅测试允许模拟服务使用 HTTP，正式启动必须使用 HTTPS Issuer。
真实服务和生产 Redis 需配置后另行联调。
