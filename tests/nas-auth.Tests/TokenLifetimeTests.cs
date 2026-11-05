using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.DependencyInjection;
using NasAuth.Services;
using NasAuth.Config;
using Xunit;
namespace NasAuth.Tests;
public sealed class TokenLifetimeTests
{
    [Theory]
    [InlineData(15, 30, 900)]
    [InlineData(1, 0, 60)]
    [InlineData(null, 1, 86400)]
    [InlineData(null, 30, 2592000)]
    public void MinutesOverrideDays_AndLegacyDaysRemainCompatible(int? minutes,int days,int expected)
    {
        var options=new JwtOptions {AccessTokenLifetimeMinutes=minutes,AccessTokenLifetimeDays=days};
        options.Validate();Assert.Equal(expected,options.EffectiveAccessTokenLifetimeSeconds);
    }
    [Theory]
    [InlineData(0,30)]
    [InlineData(-1,30)]
    [InlineData(int.MaxValue,1)]
    [InlineData(null,0)]
    [InlineData(null,int.MaxValue)]
    public void InvalidOrOverflowingLifetimesFailAtStartup(int? minutes,int days) =>
        Assert.Throws<InvalidOperationException>(()=>new JwtOptions {AccessTokenLifetimeMinutes=minutes,AccessTokenLifetimeDays=days}.Validate());
    [Fact]
    public void SignedJwtAndExpiresInUseSameMinuteBasedLifetime()
    {
        using var app=new NasAuthAppFactory();
        var options=app.Services.GetRequiredService<JwtOptions>();
        options.AccessTokenLifetimeMinutes=15;
        var issuer=app.Services.GetRequiredService<JwtIssuer>();
        var raw=issuer.IssueAccessToken("admin","test-client",["test"],"https://localhost/test","openid");
        var token=new JwtSecurityTokenHandler().ReadJwtToken(raw);
        Assert.Equal(900,issuer.AccessTokenLifetimeSeconds());
        Assert.Equal(TimeSpan.FromMinutes(15),token.ValidTo-token.ValidFrom);
    }

}
