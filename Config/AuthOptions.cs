namespace NasAuth.Config;

/// <summary>
/// 顶层 Auth:* 配置。Issuer 必须是 https://auth.<domain>。
/// </summary>
public class AuthOptions
{
    public const string SectionName = "Auth";

    public string Issuer { get; set; } = "";
    public string Database { get; set; } = "";
    public string ResourcesPath { get; set; } = "";
    public string ClientsPresetPath { get; set; } = "";
    public AdminOptions Admin { get; set; } = new();
    public PasswordLoginOptions PasswordLogin { get; set; } = new();
    public DcrOptions Dcr { get; set; } = new();
}

/// <summary>
/// 动态注册（RFC 7591 /register）的运维约束。规则本体见 Services/RedirectUriPolicy。
/// </summary>
public class DcrOptions
{
    /// <summary>
    /// https redirect_uri 的主机白名单（Auth__Dcr__AllowedRedirectHosts__0=claude.ai …）。
    /// 条目精确匹配；以 "." 开头的只匹配子域。环回 http 不受约束。
    /// 与 <see cref="AllowedCustomSchemes"/> 任一非空即进入白名单模式，两张表同时生效；都空 = 不限（默认，与原行为一致）。
    /// /register 与 DCR 客户端的 /authorize 都按它判。
    /// </summary>
    public string[] AllowedRedirectHosts { get; set; } = [];

    /// <summary>
    /// 私有 scheme 白名单（Auth__Dcr__AllowedCustomSchemes__0=cursor …），精确匹配、忽略大小写。
    /// 白名单模式下不在表里的私有 scheme 一律拒；浏览器 / 系统启动器 scheme 不管配不配都拒（见 RedirectUriPolicy）。
    /// </summary>
    public string[] AllowedCustomSchemes { get; set; } = [];
}

/// <summary>
/// 密码登录开关（外部认证设计 §十 二期）。false = 登录页/consent 隐藏密码入口、
/// 密码 endpoint 404。禁用而非删除：password_hash 留库，break-glass 时
/// 在宿主机上把 Auth__PasswordLogin__Enabled 改回 true 重启容器即恢复。
/// admin 的「建用户/重置临时密码」不受影响（新用户首登仍可能走密码改密引导，
/// 但常规路径是审批绑外部账号）。
/// </summary>
public class PasswordLoginOptions
{
    public bool Enabled { get; set; } = true;
}

public class AdminOptions
{
    public string Username { get; set; } = "admin";

    /// <summary>明文密码（启动时 hash 后即丢弃）。优先级低于 PasswordHash。</summary>
    public string Password { get; set; } = "";

    /// <summary>已经 argon2id hash 后的字符串。优先级高于 Password。</summary>
    public string PasswordHash { get; set; } = "";
}
