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
        // 统一账号中心（external-auth.md §十四）：用户自己的邮箱、按用户的密码登录开关、按账号失败锁定。
        // allow_password_login 默认 0：升级前密码登录是全局开关、常见做法是关闭，全员 0 与升级前的实际行为一致。
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN email TEXT");
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN allow_password_login INTEGER NOT NULL DEFAULT 0");
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0");
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN locked_until INTEGER");
        // 会话版本（external-auth.md §十六）：cookie 里记登录时的版本，对不上即作废。
        // 默认 0，老 cookie 没有这个 claim 也按 0 算，升级不掉线。
        TryAddColumn(conn, "ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0");
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
    default_resource TEXT
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
";
}
