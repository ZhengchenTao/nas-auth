using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace NasAuth.Services;

/// <summary>
/// argon2id 密码 hash。参数：iterations=4 / memorySize=64MB / parallelism=2。
/// 输出格式：自定义紧凑 string "$argon2id$v=19$m=65536,t=4,p=2$<base64-salt>$<base64-hash>"
/// （PHC 风格的子集，自己生成自己解析，不依赖第三方解析库）。
/// </summary>
public static class PasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Iterations = 4;
    private const int MemorySize = 65536; // 64 MB
    private const int Parallelism = 2;
    private const string Marker = "$argon2id$v=19$m=65536,t=4,p=2$";

    public static string Hash(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("密码不能为空", nameof(password));

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = ComputeHash(password, salt);

        return $"{Marker}{Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string password, string encoded)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(encoded)) return false;
        if (!encoded.StartsWith(Marker)) return false;

        try
        {
            var rest = encoded.Substring(Marker.Length);
            var parts = rest.Split('$');
            if (parts.Length != 2) return false;
            var salt = Convert.FromBase64String(parts[0]);
            var expected = Convert.FromBase64String(parts[1]);
            var actual = ComputeHash(password, salt);
            return CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        catch
        {
            return false;
        }
    }

    private static byte[] ComputeHash(string password, byte[] salt)
    {
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = Parallelism,
            Iterations = Iterations,
            MemorySize = MemorySize,
        };
        return argon2.GetBytes(HashSize);
    }
}
