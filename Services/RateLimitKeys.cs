using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Http;

namespace NasAuth.Services;

/// <summary>
/// 限速分区键（auth-sensitive 与 dcr 两个策略共用）。
/// IPv4 按完整地址；IPv6 按 /64 前缀 —— 一个家宽 / 云主机通常分到整段 /64，按完整地址分区的话
/// 换个接口标识就是新桶，限速形同虚设。IPv4 映射的 IPv6（::ffff:a.b.c.d）按 IPv4 处理。
/// </summary>
public static class RateLimitKeys
{
    public static string ClientKey(HttpContext ctx) => ClientKey(ctx.Connection.RemoteIpAddress);

    public static string ClientKey(IPAddress? ip)
    {
        if (ip is null) return "unknown";
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily != AddressFamily.InterNetworkV6) return ip.ToString();
        var bytes = ip.GetAddressBytes();
        Array.Clear(bytes, 8, 8);
        return new IPAddress(bytes).ToString() + "/64";
    }
}
