# Application configuration and access diagnostics

Open **Apps & resources → an application capability → Check configuration and access**.
Choose a resource, search by name, username or email, and select the intended account.
Search includes active and disabled accounts, with at most 25 of each per query. Selection
uses the stable user ID, so reusing a sign-in name does not silently select the retired identity.

The page requires a current Auth administrator session and is not cached. It does not
change grants, call external providers, retry provisioning, or log in as the selected user.

Configuration checks cover loaded preset-client default resources, credentials for
confidential clients, callback URL syntax, exact configured callbacks, and client/audience
collisions. Issuer and discovery URLs include the deployment's public path prefix.
OAuth/MCP clients that explicitly specify a resource do not need a preset default;
a missing preset association is advisory, not a denial. Startup validation continues
to reject malformed resource/provider configuration before the application starts.

Access checks distinguish disabled/missing identities, configured sign-in methods,
password lockout and mandatory password change, administrator-only resources,
effective scopes, and direct/group grant sources. Partial scope grants are displayed
as partial, not as a complete application denial. Each capability is checked separately.

For configured account synchronization the page compares current desired access with
the last delivery state, including all required resources/scopes. A successful delivery
means the adapter acknowledged it; it does not prove that an application administrator
has not subsequently changed the account. Application roles and existing sessions are
outside this local diagnosis. Use **Manage** to review access and retry synchronization
through the existing audited user-management flow.

## 中文

入口：**应用与资源 → 展开应用能力 → 检查配置与访问**。选择资源后，可按姓名、用户名、
邮箱搜索正常和停用账号，再选择具体身份。实际选择使用固定用户 ID，避免复用用户名时误选旧身份。

检查包括预置客户端默认资源、机密客户端凭据是否存在、回调地址格式、配置的精确回调地址、
客户端与资源 audience 冲突，以及账号状态、登录条件、scope 和个人/组授权来源。
配置仍由部署文件管理，修改后重启生效；页面不保存另一份配置。

配置了账号同步时，同时显示期望启停状态与最近一次投递结果。“已确认投递”不代表下游实时状态
或已有会话已经验证。页面只读、仅管理员可用，不联系外部服务、不修改权限；需要处理时进入
已有的用户管理页。完整验证仍需真实登录、应用内部权限与撤权检查。

Preset clients are explicitly trusted; the DCR redirect-host allowlist applies only to dynamic clients and is not used to reject preset callback addresses here.
