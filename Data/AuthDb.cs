using Microsoft.Data.Sqlite;
using NasAuth.Config;

namespace NasAuth.Data;

/// <summary>
/// SQLite 连接工厂 + 启动时建表。直接执行 CREATE TABLE IF NOT EXISTS，不引 EF Core。
/// 外部身份 / 用户级授权表见 external-auth.md §四，另有一张 settings k/v 表。
/// </summary>
public class AuthDb
{
    private readonly string _connectionString;

    public AuthDb(AuthOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.Database))
            throw new InvalidOperationException("Auth:Database 未配置");
        _connectionString = options.Database;
    }

    public SqliteConnection OpenConnection()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        // SQLite 性能 / 一致性兜底
        using (var pragma = conn.CreateCommand())
        {
            pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;";
            pragma.ExecuteNonQuery();
        }
        return conn;
    }

    /// <summary>
    /// 启动期间执行：建立目录 + CREATE TABLE IF NOT EXISTS 全部表。
    /// 任何失败都抛，让宿主进程 crash（fast fail，不掩盖配置/权限错误）。
    /// </summary>
    public void EnsureCreated()
    {
        EnsureDataDirectory();
        using var conn = OpenConnection();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = SchemaSql;
            cmd.ExecuteNonQuery();
        }
        // 老 DB 升级：users 表加 is_admin / must_change_password。SQLite 没有 IF NOT EXISTS
        // 的 ADD COLUMN，靠 "duplicate column name" 异常吞掉即可（idempotent）。
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0");
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0");
        // P5 OIDC：auth_codes 记 nonce（id_token 回显）；clients 记 default_resource
        // （非 RFC 8707 客户端如 Gitea 不发 resource 参数，按 client 兜底）。
        TryAddColumn(conn, "ALTER TABLE auth_codes ADD COLUMN nonce TEXT");
        TryAddColumn(conn, "ALTER TABLE clients ADD COLUMN default_resource TEXT");
        // 按客户端附加的固定 claim（§二十一）：JSON 对象，值为字符串或字符串数组；只有预置客户端会有
        TryAddColumn(conn, "ALTER TABLE clients ADD COLUMN extra_claims TEXT");
        // 统一账号中心（external-auth.md §十四）：用户自己的邮箱、按用户的密码登录开关、按账号失败锁定。
        // allow_password_login 默认 0：升级前密码登录是全局开关、常见做法是关闭，全员 0 与升级前的实际行为一致。
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN email TEXT");
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN allow_password_login INTEGER NOT NULL DEFAULT 0");
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0");
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN locked_until INTEGER");
        // 会话版本（external-auth.md §十六）：cookie 里记登录时的版本，对不上即作废。
        // 默认 0，老 cookie 没有这个 claim 也按 0 算，升级不掉线。
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0");
        // 昵称与头像（external-auth.md §十九）：用户 id 不可改、各应用按它认人；昵称（下发 name）与头像（下发 picture）可改。
        // external_identities.avatar = 该外部账号最近一次登录时缓存下来的头像文件，供用户手动选用。
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN display_name TEXT");
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN avatar TEXT");
        TryAddColumn(conn, "ALTER TABLE external_identities ADD COLUMN avatar TEXT");
        TryAddColumn(conn, "ALTER TABLE external_identities ADD COLUMN profile_json TEXT");
        TryAddColumn(conn, "ALTER TABLE external_identities ADD COLUMN profile_updated_at INTEGER");
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN is_disabled INTEGER NOT NULL DEFAULT 0");
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN session_epoch TEXT NOT NULL DEFAULT ''");
        using (var provisioning = conn.CreateCommand())
        {
            provisioning.CommandText = ProvisioningSchema;
            provisioning.ExecuteNonQuery();
        }
        TryAddColumn(conn, "ALTER TABLE provisioning_changes ADD COLUMN application_id TEXT");
        TryAddColumn(conn, "ALTER TABLE deleted_user_ids ADD COLUMN username TEXT COLLATE NOCASE");
        using (var links = conn.CreateCommand())
        {
            links.CommandText = CredentialLinkSchema;
            links.ExecuteNonQuery();
        }
        BackfillDisplayNamesOnce(conn);
    }

    /// <summary>
    /// §十九 一次性回填：老用户的昵称取他第一条 active 外部身份的名字（google 优先，按 provider 字典序）——
    /// 与升级前下发的 name 一致，升级后各应用看到的名字不变。没有外部身份的留空：下发时本来就回落到 user_id，
    /// 填了反而挡住「首次绑定时从外部账号取昵称」（2026-10-02 首版填了 user_id，预建好等人来登的 jelly 因此拿不到微软账号的名字）。
    /// 只跑一次（settings 标志位）。
    /// </summary>
    private static void BackfillDisplayNamesOnce(Microsoft.Data.Sqlite.SqliteConnection conn)
    {
        const string flag = "display_name_backfilled_v1";
        using (var check = conn.CreateCommand())
        {
            check.CommandText = "SELECT COUNT(*) FROM settings WHERE key = $k";
            check.Parameters.AddWithValue("$k", flag);
            if ((long)check.ExecuteScalar()! > 0) return;
        }
        using var tx = conn.BeginTransaction();
        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = @"
                UPDATE users SET display_name =
                    (SELECT e.display_name FROM external_identities e
                      WHERE e.user_id = users.user_id AND e.status = 'active'
                        AND e.display_name IS NOT NULL AND e.display_name <> ''
                      ORDER BY e.provider LIMIT 1)
                WHERE display_name IS NULL OR display_name = '';
                INSERT INTO settings (key, value, updated_at) VALUES ($k, '1', strftime('%s','now'));";
            cmd.Parameters.AddWithValue("$k", flag);
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    private static void TryAddColumn(Microsoft.Data.Sqlite.SqliteConnection conn, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        try { cmd.ExecuteNonQuery(); }
        catch (Microsoft.Data.Sqlite.SqliteException ex)
            when (ex.Message.Contains("duplicate column name", StringComparison.OrdinalIgnoreCase))
        {
            // 列已存在，安静跳过
        }
    }

    private void EnsureDataDirectory()
    {
        // 解析 "Data Source=/app/data/auth.db" 这种字符串里的目录
        var builder = new SqliteConnectionStringBuilder(_connectionString);
        var path = builder.DataSource;
        if (string.IsNullOrWhiteSpace(path) || path == ":memory:") return;
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);
    }

    private const string CredentialLinkSchema = """
CREATE TABLE IF NOT EXISTS credential_links (
    id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    purpose TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    state TEXT NOT NULL, used_at INTEGER, created_by TEXT NOT NULL, stamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credential_links_user ON credential_links(user_id,created_at);
CREATE TRIGGER IF NOT EXISTS credential_links_user_changed
AFTER UPDATE OF password_hash,session_version,session_epoch,allow_password_login,is_disabled,is_admin,email ON users
WHEN OLD.password_hash IS NOT NEW.password_hash OR OLD.session_version IS NOT NEW.session_version
 OR OLD.session_epoch IS NOT NEW.session_epoch OR OLD.allow_password_login IS NOT NEW.allow_password_login
 OR OLD.is_disabled IS NOT NEW.is_disabled OR OLD.is_admin IS NOT NEW.is_admin OR OLD.email IS NOT NEW.email
BEGIN UPDATE credential_links SET state='revoked' WHERE user_id=NEW.user_id AND state='pending'; END;
""";

    private const string ProvisioningSchema = @"
CREATE TABLE IF NOT EXISTS provisioning_changes (
    revision INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS provisioning_accounts (
    application_id TEXT NOT NULL, user_id TEXT NOT NULL, revision INTEGER NOT NULL,
    enabled INTEGER NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0,
    error_code TEXT, delivered_at INTEGER, PRIMARY KEY(application_id,user_id)
);
CREATE TRIGGER IF NOT EXISTS provisioning_user_insert AFTER INSERT ON users
WHEN (SELECT value FROM settings WHERE key='provisioning_enabled')='1'
BEGIN INSERT INTO provisioning_changes(user_id) VALUES(NEW.user_id); END;
CREATE TRIGGER IF NOT EXISTS provisioning_user_update AFTER UPDATE OF username,display_name,email,is_disabled,is_admin ON users
WHEN (SELECT value FROM settings WHERE key='provisioning_enabled')='1'
BEGIN INSERT INTO provisioning_changes(user_id) VALUES(NEW.user_id); END;
CREATE TRIGGER IF NOT EXISTS provisioning_user_delete AFTER DELETE ON users
WHEN (SELECT value FROM settings WHERE key='provisioning_enabled')='1'
BEGIN INSERT INTO provisioning_changes(user_id) VALUES(OLD.user_id); END;
CREATE TRIGGER IF NOT EXISTS provisioning_grant_insert AFTER INSERT ON user_resources
WHEN (SELECT value FROM settings WHERE key='provisioning_enabled')='1'
BEGIN INSERT INTO provisioning_changes(user_id) VALUES(NEW.user_id); END;
CREATE TRIGGER IF NOT EXISTS provisioning_grant_update AFTER UPDATE ON user_resources
WHEN (SELECT value FROM settings WHERE key='provisioning_enabled')='1'
BEGIN INSERT INTO provisioning_changes(user_id) VALUES(NEW.user_id); END;
CREATE TRIGGER IF NOT EXISTS provisioning_grant_delete AFTER DELETE ON user_resources
WHEN (SELECT value FROM settings WHERE key='provisioning_enabled')='1'
BEGIN INSERT INTO provisioning_changes(user_id) VALUES(OLD.user_id); END;
-- Bootstrap seeds are not reviewed administrator grants. The worker enables
-- change capture only after startup initialization has finished.
INSERT INTO settings(key,value,updated_at) VALUES('provisioning_enabled','0',0)
ON CONFLICT(key) DO UPDATE SET value='0';
";

    private const string SchemaSql = @"
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    client_secret_hash TEXT,
    client_name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none',
    auto_registered INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    default_resource TEXT,
    extra_claims TEXT
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    scope TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    nonce TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    scope TEXT NOT NULL,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client ON refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    email TEXT,
    allow_password_login INTEGER NOT NULL DEFAULT 0,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    session_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 外部身份绑定 + 审批状态（外部认证设计 §四）。
-- 身份主键是 (provider, subject)，绝不用 email 匹配账号（email 可变可回收）。
-- status: pending（等管理员批准，user_id 为 NULL）/ active（已绑定 user_id，可登录）
--         / rejected（已拒绝，记录保留防重复申请刷屏）。
CREATE TABLE IF NOT EXISTS external_identities (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id TEXT,
    email TEXT,
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    approved_at INTEGER,
    PRIMARY KEY (provider, subject)
);
CREATE INDEX IF NOT EXISTS idx_external_identities_user ON external_identities(user_id);
CREATE INDEX IF NOT EXISTS idx_external_identities_status ON external_identities(status);

-- 用户级资源授权（外部认证设计 §四）：(user, aud) → 授予的最大 scope（空格分隔）。
-- /authorize 检查（P4）：行存在 且 请求 scope ⊆ scopes，否则 access_denied。
-- 审计事件（external-auth.md §十六）：与 stdout 的 audit.* 日志同源，入库供后台查询，保留 90 天。
-- event：login / external_login / authorize / token / revoke / register / proxy.deny / account.<动作>。
-- 高频的 proxy 转发与 introspect 不入库。detail 里绝不放 token。
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    event TEXT NOT NULL,
    success INTEGER NOT NULL,
    user_id TEXT,
    client_id TEXT,
    ip TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);

CREATE TABLE IF NOT EXISTS user_resources (
    user_id TEXT NOT NULL,
    aud TEXT NOT NULL,
    scopes TEXT NOT NULL,
    PRIMARY KEY (user_id, aud)
);

CREATE TABLE IF NOT EXISTS access_groups (
    id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE
);
CREATE TABLE IF NOT EXISTS access_group_members (
    group_id TEXT NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    PRIMARY KEY(group_id,user_id)
);
CREATE INDEX IF NOT EXISTS idx_access_group_members_user ON access_group_members(user_id);
CREATE TABLE IF NOT EXISTS access_group_resources (
    group_id TEXT NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
    aud TEXT NOT NULL, scopes TEXT NOT NULL, PRIMARY KEY(group_id,aud)
);
CREATE VIEW IF NOT EXISTS resource_grant_sources AS
    SELECT user_id,aud,scopes,NULL AS group_id FROM user_resources
    UNION ALL
    SELECT m.user_id,r.aud,r.scopes,m.group_id
    FROM access_group_members m JOIN access_group_resources r ON r.group_id=m.group_id;

-- 预绑定邮箱（external-auth.md §十八）：管理员给某个用户登记一个邮箱，日后首次用 Google 登录、
-- 且 Google 声明该邮箱已验证（email_verified）的外部身份，直接绑到这个用户、不进待批。用一次即删。
CREATE TABLE IF NOT EXISTS external_invites (
    email TEXT NOT NULL PRIMARY KEY,   -- 小写
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    created_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_external_invites_user ON external_invites(user_id);

-- 删过的 user_id（§十八）：user_id 就是下发给各应用的 sub / preferred_username，应用按它认账号；
-- 删人后永久保留原身份。确认复用登录名时，另发新的 user_id。
CREATE TABLE IF NOT EXISTS deleted_user_ids (
    user_id TEXT NOT NULL PRIMARY KEY COLLATE NOCASE,
    deleted_at INTEGER NOT NULL
);
";
}
