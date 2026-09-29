using NasAuth.Config;
using NasAuth.Data.Repositories;

namespace NasAuth.Services;

/// <summary>
/// 密码登录的实际生效判定（设计 §十 二期的运行时增强）。
/// 三层叠加，从低到高：
///   1. 配置基线 Auth__PasswordLogin__Enabled（重启生效，break-glass 兜底不变）
///   2. settings 表运行时 override（admin 在 /admin/system 一键切，立即生效）——
///      典型场景：配置常关，临时打开放一个人进来，用完再恢复跟随配置
///   3. 防锁死兜底：Google/Microsoft 都未配置时强制视为开，否则没有任何登录入口
/// </summary>
public class PasswordLoginGate
{
    /// <summary>settings 键。值 "enabled" / "disabled"；行不存在 = 跟随配置。</summary>
    public const string OverrideKey = "auth.password_login.override";

    private readonly AuthOptions _auth;
    private readonly SettingsRepository _settings;
    private readonly ExternalProviderOptions _providers;

    public PasswordLoginGate(AuthOptions auth, SettingsRepository settings, ExternalProviderOptions providers)
    {
        _auth = auth;
        _settings = settings;
        _providers = providers;
    }

    public bool ConfigEnabled => _auth.PasswordLogin.Enabled;

    /// <summary>当前 override：true/false，null = 未设置（跟随配置）。</summary>
    public bool? Override => _settings.Get(OverrideKey) switch
    {
        "enabled" => true,
        "disabled" => false,
        _ => null,
    };

    public bool LockoutGuardActive => !_providers.GoogleEnabled && !_providers.MicrosoftEnabled;

    /// <summary>
    /// 总闸实际生效值：决定登录页显不显示密码框、密码 endpoint 开不开。
    /// 开了之后具体某个用户能不能用密码，再看 <see cref="AllowsUser"/>（external-auth.md §十四）。
    /// </summary>
    public bool Enabled => LockoutGuardActive || (Override ?? ConfigEnabled);

    /// <summary>
    /// 某用户此刻能否用密码登录 = 总闸开 且 该用户 allow_password_login=1。
    /// 防锁死兜底优先：没配任何外部 provider 时所有用户都放行（否则连管理员都进不来）。
    /// </summary>
    public bool AllowsUser(NasAuth.Data.UserRow user) =>
        LockoutGuardActive || (Enabled && user.allow_password_login != 0);

    /// <summary>设置 / 清除运行时 override。null = 清除（恢复跟随配置）。</summary>
    public void SetOverride(bool? enabled)
    {
        if (enabled is null) _settings.Delete(OverrideKey);
        else _settings.Set(OverrideKey, enabled.Value ? "enabled" : "disabled");
    }
}
