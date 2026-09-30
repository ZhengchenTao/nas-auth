using NasAuth.Data.Repositories;

namespace NasAuth.Services;

/// <summary>
/// 启动期一次性 seed（外部认证设计 §四）：给"迁移时刻已存在的全部用户"插入
/// 每个已注册 aud 的全量 scope user_resources 行，保证升级后行为不变 ——
/// 升级前没有用户级授权检查，任何用户都能授权任何资源；只 seed 管理员会在
/// P4（/authorize 检查）上线时切断其余既有用户。
/// 只跑一次（settings 标志位），之后管理员对 user_resources 的手动收窄 / 删行
/// 不会被重启覆盖；新建用户的授权由审批 / 用户管理页显式勾选。
/// </summary>
public static class UserResourceSeeder
{
    private const string SeededFlagKey = "user_resources_seeded_v1";

    public static void SeedIfNeeded(
        ResourceCatalog catalog,
        UserRepository users,
        UserResourceRepository userResources,
        SettingsRepository settings,
        ILogger logger)
    {
        if (settings.Get(SeededFlagKey) == "1")
        {
            logger.LogInformation("user_resources 已 seed 过（{Flag}），跳过", SeededFlagKey);
            return;
        }

        var allUsers = users.ListAll();
        foreach (var user in allUsers)
        {
            foreach (var resource in catalog.All.Where(r => r.AllowsUser(user.is_admin != 0)))
            {
                userResources.Upsert(user.user_id, resource.Aud, string.Join(' ', resource.Scopes));
            }
        }

        settings.Set(SeededFlagKey, "1");
        logger.LogInformation("user_resources seed 完成：{Users} 个用户 × {Auds} 个 aud（全量 scope）",
            allUsers.Count, catalog.All.Count);
    }
}
