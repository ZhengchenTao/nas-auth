using NasAuth.Config;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

/// <summary>
/// 启动期间根据 Auth:Admin:* 配置 upsert 管理员账号。
///  - PasswordHash 优先（运维直接灌已 hash 值）
///  - 否则用 Password 明文，运行时 hash 后写库 → 内存里立即丢弃
///  - 两个都为空：只有当数据库已经存在该用户才放行；否则启动失败
/// </summary>
public static class AdminBootstrapper
{
    public static void EnsureAdmin(AuthOptions auth, UserRepository users, ILogger logger)
    {
        var username = string.IsNullOrWhiteSpace(auth.Admin.Username) ? "admin" : auth.Admin.Username;

        var hash = auth.Admin.PasswordHash;
        if (string.IsNullOrWhiteSpace(hash) && !string.IsNullOrWhiteSpace(auth.Admin.Password))
        {
            hash = PasswordHasher.Hash(auth.Admin.Password);
            // 注意：不打印明文，也不打印 hash
            logger.LogInformation("已根据 Auth:Admin:Password 生成 argon2id hash 并写入 users 表");
        }

        if (!string.IsNullOrWhiteSpace(hash))
        {
            // 用 username 作 user_id（不强制 GUID，username 即 user_id 可读性更好）
            // 该用户是 super admin，is_admin=1 每次启动强制重置（即使 SQL 被手改也兜底回来）
            users.Upsert(userId: username, username: username, passwordHash: hash, isAdmin: true);
        }
        else
        {
            var existing = users.GetByUsername(username);
            if (existing is null)
            {
                throw new InvalidOperationException(
                    "Auth:Admin:Password / Auth:Admin:PasswordHash 都未配置，且 users 表中不存在该用户。" +
                    "首次启动必须至少提供其中一个。");
            }
            // 已存在但 is_admin=0 的话兜底拉回 admin（迁移老 DB 必经路径）
            if (existing.is_admin == 0)
            {
                users.Upsert(userId: existing.user_id, username: existing.username,
                    passwordHash: existing.password_hash, isAdmin: true);
                logger.LogInformation("管理员 {User} 已存在但 is_admin=0，已升级为 super admin", username);
            }
            else
            {
                logger.LogInformation("管理员 {User} 已存在于 users 表，跳过 bootstrap", username);
            }
        }
    }
}
