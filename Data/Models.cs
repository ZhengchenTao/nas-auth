namespace NasAuth.Data;

// 这些 record 字段命名直接对齐 SQLite 列名（snake_case），
// Dapper 默认大小写不敏感映射，不用额外的列映射器。

// 列序注意事项见下方 UserRow 注释：ALTER ADD COLUMN 追加到表尾，新字段只能排最后。
public record ClientRow(
    string client_id,
    string? client_secret_hash,
    string client_name,
    string redirect_uris,
    string token_endpoint_auth_method,
    long auto_registered,
    long created_at,
    long? last_used_at,
    string? default_resource
);

public record AuthCodeRow(
    string code,
    string client_id,
    string resource,
    string scope,
    string redirect_uri,
    string code_challenge,
    string code_challenge_method,
    string user_id,
    long expires_at,
    long consumed,
    long created_at,
    string? nonce
);

public record RefreshTokenRow(
    string token_hash,
    string client_id,
    string resource,
    string scope,
    string user_id,
    long expires_at,
    long revoked,
    long created_at,
    long? last_used_at
);

// 注意字段顺序：Dapper 对 positional record 按 reader 列序匹配构造参数，
// SQLite 的 ALTER TABLE ADD COLUMN 把新列追加到表尾，所以 is_admin / must_change_password
// 必须排在 created_at/updated_at 之后，否则 SELECT * 对老 DB 会 materialization 失败。
// CREATE TABLE 的列序也要与此一致。修改顺序前先确认所有 INSERT/SELECT 也同步更新。
// email / allow_password_login / failed_login_count / locked_until 同理追加在最后（external-auth.md §十四），
// session_version 再其后（§十六）。
public record UserRow(
    string user_id,
    string username,
    string password_hash,
    long created_at,
    long updated_at,
    long is_admin,
    long must_change_password,
    string? email,
    long allow_password_login,
    long failed_login_count,
    long? locked_until,
    long session_version
);

// status 语义见 AuthDb 建表注释：pending（user_id 为 NULL）/ active / rejected。
public record ExternalIdentityRow(
    string provider,
    string subject,
    string? user_id,
    string? email,
    string? display_name,
    string status,
    long created_at,
    long? approved_at
);

public record UserResourceRow(
    string user_id,
    string aud,
    string scopes
);

public record AuditRow(
    long id,
    long ts,
    string @event,
    long success,
    string? user_id,
    string? client_id,
    string? ip,
    string? detail
);
