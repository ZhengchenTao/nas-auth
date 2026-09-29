namespace NasAuth.Config;

/// <summary>
/// 上游 IdP 凭证（外部认证设计 §六）。只从环境变量读（生产由 compose 的 env_file 等方式注入），
/// 不进 appsettings / 不进 git。某个 provider 的 id/secret 不全 → 该 provider 视为未启用：
/// 不注册 handler、登录页不渲染按钮、start endpoint 404。
/// 故意不 fast fail —— 外部登录是增量能力，本地开发 / 测试 / 凭证未配齐的生产都应能照常跑密码登录。
/// </summary>
public class ExternalProviderOptions
{
    public string GoogleClientId { get; init; } = "";
    public string GoogleClientSecret { get; init; } = "";
    public string MicrosoftClientId { get; init; } = "";
    public string MicrosoftClientSecret { get; init; } = "";

    public bool GoogleEnabled =>
        !string.IsNullOrWhiteSpace(GoogleClientId) && !string.IsNullOrWhiteSpace(GoogleClientSecret);

    public bool MicrosoftEnabled =>
        !string.IsNullOrWhiteSpace(MicrosoftClientId) && !string.IsNullOrWhiteSpace(MicrosoftClientSecret);

    public bool IsEnabled(string provider) => provider switch
    {
        "google" => GoogleEnabled,
        "microsoft" => MicrosoftEnabled,
        _ => false,
    };

    public static ExternalProviderOptions FromEnvironment() => new()
    {
        GoogleClientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") ?? "",
        GoogleClientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET") ?? "",
        MicrosoftClientId = Environment.GetEnvironmentVariable("MS_CLIENT_ID") ?? "",
        MicrosoftClientSecret = Environment.GetEnvironmentVariable("MS_CLIENT_SECRET") ?? "",
    };
}
