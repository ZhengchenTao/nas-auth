using NasAuth.Services;
using Xunit;

namespace NasAuth.Tests;

public class PasswordHasherTests
{
    [Fact]
    public void Hash_Then_Verify_Succeeds()
    {
        var pwd = "correct horse battery staple";
        var encoded = PasswordHasher.Hash(pwd);
        Assert.True(PasswordHasher.Verify(pwd, encoded));
    }

    [Fact]
    public void Verify_WrongPassword_Fails()
    {
        var encoded = PasswordHasher.Hash("right");
        Assert.False(PasswordHasher.Verify("wrong", encoded));
    }

    [Fact]
    public void Hash_DifferentSaltsEachCall()
    {
        var a = PasswordHasher.Hash("same");
        var b = PasswordHasher.Hash("same");
        // 两次 hash 必须不同（盐不同），但都能 verify
        Assert.NotEqual(a, b);
        Assert.True(PasswordHasher.Verify("same", a));
        Assert.True(PasswordHasher.Verify("same", b));
    }

    [Fact]
    public void Verify_GarbageEncoded_ReturnsFalse()
    {
        Assert.False(PasswordHasher.Verify("any", "not-an-argon-hash"));
        Assert.False(PasswordHasher.Verify("any", ""));
        Assert.False(PasswordHasher.Verify("", "any"));
    }

    [Fact]
    public void Hash_EmptyPassword_Throws()
    {
        Assert.Throws<ArgumentException>(() => PasswordHasher.Hash(""));
    }
}
