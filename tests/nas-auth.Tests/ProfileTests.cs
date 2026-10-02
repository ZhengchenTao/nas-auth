using Microsoft.Extensions.Logging.Abstractions;
using NasAuth.Config;
using NasAuth.Data;
using NasAuth.Data.Repositories;
using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

/// <summary>external-auth.md §十九：昵称与头像（存储、下发、补空、老库回填）。</summary>
public class ProfileTests : IDisposable
{
    private static readonly byte[] Png = Convert.FromBase64String(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==");

    private readonly string _tmpDir;
    private readonly AuthDb _db;
    private readonly UserRepository _users;
    private readonly ExternalIdentityRepository _identities;
    private readonly ProfileService _profiles;

    public ProfileTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), "nas-auth-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpDir);
        var options = new AuthOptions
        {
            Database = $"Data Source={Path.Combine(_tmpDir, "auth.db")}",
            Issuer = "https://auth.example.com",
        };
        _db = new AuthDb(options);
        _db.EnsureCreated();
        _users = new UserRepository(_db);
        _identities = new ExternalIdentityRepository(_db);
        _profiles = new ProfileService(options, NullLogger<ProfileService>.Instance);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* ignore */ }
    }

    [Fact]
    public void DetectImageType_OnlyRasterFormats()
    {
        Assert.Equal("png", ProfileService.DetectImageType(Png));
        Assert.Equal("jpg", ProfileService.DetectImageType(new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0, 0 }));
        Assert.Equal("webp", ProfileService.DetectImageType("RIFF\0\0\0\0WEBPVP8 "u8));
        Assert.Null(ProfileService.DetectImageType("<svg xmlns='http://www.w3.org/2000/svg'/>"u8));
        Assert.Null(ProfileService.DetectImageType("GIF89a"u8));
        Assert.Null(ProfileService.DetectImageType("<html><script>"u8));
    }

    [Fact]
    public void Store_IsContentAddressed_AndRejectsNonImagesAndOversize()
    {
        var a = _profiles.Store(Png)!;
        Assert.Matches(@"^[0-9a-f]{32}\.png$", a);
        Assert.Equal(a, _profiles.Store(Png));                       // 同内容同文件名
        Assert.NotNull(_profiles.PathFor(a));

        Assert.Null(_profiles.Store("<svg/>"u8.ToArray()));
        var huge = new byte[ProfileService.MaxAvatarBytes + 1];
        Png.CopyTo(huge, 0);
        Assert.Null(_profiles.Store(huge));
    }

    [Theory]
    [InlineData("../auth.db")]
    [InlineData("..%2Fauth.db")]
    [InlineData("abc.png")]
    [InlineData("0123456789abcdef0123456789abcdef.svg")]
    public void PathFor_RejectsAnythingButStoredNames(string file) => Assert.Null(_profiles.PathFor(file));

    [Fact]
    public void Resolve_NamePrecedence_NicknameThenExternalThenUserId_AndPictureUrl()
    {
        _users.Create("jelly", "jelly", PasswordHasher.UnusableHash(), mustChangePassword: false);
        Assert.Equal("jelly", _profiles.Resolve(_identities, _users, "jelly").Name);

        _identities.BindActive("microsoft", "ms-1", "jelly", "jelly@outlook.com", "Jelly Miao");
        Assert.Equal("Jelly Miao", _profiles.Resolve(_identities, _users, "jelly").Name);

        _users.UpdateDisplayName("jelly", "  小果冻  ");
        var file = _profiles.Store(Png)!;
        _users.UpdateAvatar("jelly", file);
        var (_, name, picture) = _profiles.Resolve(_identities, _users, "jelly");
        Assert.Equal("小果冻", name);
        Assert.Equal($"https://auth.example.com/avatars/{file}", picture);
    }

    [Fact]
    public void FillProfileIfEmpty_NeverOverwritesWhatUserSet()
    {
        _users.Create("bob", "bob", PasswordHasher.UnusableHash(), mustChangePassword: false);
        _users.FillProfileIfEmpty("bob", "Bob From Google", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.png");
        var u = _users.GetById("bob")!;
        Assert.Equal(("Bob From Google", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.png"), (u.display_name, u.avatar));

        _users.UpdateDisplayName("bob", "Bobby");
        _users.FillProfileIfEmpty("bob", "Bob From Microsoft", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.png");
        u = _users.GetById("bob")!;
        Assert.Equal(("Bobby", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.png"), (u.display_name, u.avatar));
    }

    [Fact]
    public void IdentitySnapshot_KeepsOldValuesWhenNewAreNull()
    {
        _users.Create("bob", "bob", PasswordHasher.UnusableHash(), mustChangePassword: false);
        _identities.BindActive("google", "g-1", "bob", "b@example.com", "Bob");
        _identities.UpdateSnapshot("google", "g-1", "Bob New", "cccccccccccccccccccccccccccccccc.jpg");
        _identities.UpdateSnapshot("google", "g-1", null, null);      // 这次没拿到头像
        var row = _identities.Get("google", "g-1")!;
        Assert.Equal(("Bob New", "cccccccccccccccccccccccccccccccc.jpg"), (row.display_name, row.avatar));
    }

    [Fact]
    public void OldDatabase_BackfillsNicknameOnce_FromExternalNameOnly()
    {
        // 新库：先建用户，再模拟「老库还没回填」——清掉标志位重跑 EnsureCreated
        _users.Create("withext", "withext", "h", mustChangePassword: false);
        _users.Create("plain", "plain", "h", mustChangePassword: false);
        _identities.BindActive("google", "g-1", "withext", "w@example.com", "With Ext");
        using (var conn = _db.OpenConnection())
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE users SET display_name = NULL; DELETE FROM settings WHERE key = 'display_name_backfilled_v1';";
            cmd.ExecuteNonQuery();
        }

        _db.EnsureCreated();
        Assert.Equal("With Ext", _users.GetById("withext")!.display_name);
        // 没有外部身份的留空：下发时回落到 user_id；留空才能让以后首次绑定时补上外部账号的名字
        Assert.Null(_users.GetById("plain")!.display_name);
        Assert.Equal("plain", _profiles.Resolve(_identities, _users, "plain").Name);

        // 只跑一次：之后清空的昵称不会被下次启动又填回去
        _users.UpdateDisplayName("withext", null);
        _db.EnsureCreated();
        Assert.Null(_users.GetById("withext")!.display_name);
    }
}
