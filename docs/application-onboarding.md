# Application onboarding and preflight

Administrators open **Connected apps → Connect an application** (`/admin/apps/new`).
Choose OIDC, forward-auth or MCP, enter the public resource address and exact OIDC callbacks,
and review the generated resource/client entries and receiving-application settings.
The wizard checks identifier/address collisions and does not save deployment files, register
clients, create grants or contact the receiving service. Merge entries into the existing arrays.
Application permissions remain in the application. Follow the existing forward-auth deployment
guide for proxy routing and trusted headers; the generated verify URL alone is insufficient.

For confidential clients, the generated preset uses `client_secret_env`. Generate the secret in
the deployment's secret manager, inject the named environment variable into Auth, and configure
the same credential in the client. Existing `client_secret` presets remain compatible; set one
credential source only. No secret is generated or displayed by the wizard.

## Validate before restarting

Run the release image with the same proposed configuration mounts and environment as the service:

```sh
docker compose run --rm --no-deps auth --check-config
# Or from a published runtime:
dotnet nas-auth.dll --check-config
```

Replace `auth` with the Compose service name. A custom entrypoint must forward its arguments
to `dotnet`; otherwise explicitly run `/app/nas-auth.dll --check-config` through the dotnet
entrypoint while preserving the deployment's normal credential injection.

The command exits 0 for valid configuration and 2 for errors, with a JSON report by area.
It does not start the web host, open the database, generate keys, deliver account synchronization
events or make network requests. It validates issuer/path, JWT settings, branding, providers,
profile schema, resources, clients, required credential environment variables and provisioning
references. Missing explicitly configured preset files are errors even though ordinary startup
historically permits their absence. Preset callback syntax is checked independently of DCR
host allowlists. Errors omit configuration values and exception details to avoid leaking secrets.

A successful preflight does not prove database writability, TLS/proxy routing, external provider
availability or application integration. Restart Auth, check application diagnostics, then verify
a real login and revocation flow. For MCP resource metadata see
[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html); receivers must validate the token themselves.

## 中文

管理员从「应用 → 接入应用」选择 OIDC、入口保护或 MCP，生成资源、客户端和接入方配置。
向导核对地址和标识冲突，只生成片段，不覆盖文件或自动授予权限。公司实例仍只维护部署配置。
机密客户端通过 `client_secret_env` 引用环境变量，凭据在密钥管理器中生成并注入。

上线前用待部署的配置和环境运行 `--check-config`：成功退出 0，失败退出 2，并按配置区输出 JSON。
检查不会启动服务、打开数据库、生成密钥或访问外部系统；错误输出不含凭据值。
通过后仍需重启、检查应用诊断，并执行实际登录与撤权验收。
