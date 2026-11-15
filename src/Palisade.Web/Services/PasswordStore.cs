using System.Security.Cryptography;
using System.Text.Json;

namespace Palisade.Web.Services;

/// <summary>The single admin password, stored as a salted PBKDF2 hash in the web UI's own data folder.</summary>
public sealed class PasswordStore(string dataDirectory)
{
    public const int MinimumLength = 10;
    private const int Iterations = 600_000;
    private readonly string _path = Path.Combine(dataDirectory, "auth.json");
    private readonly Lock _lock = new();
    private int _recentFailures;

    private sealed record Stored(string Salt, string Hash, int Iterations);

    public bool HasPassword => File.Exists(_path);

    public void Set(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
        Directory.CreateDirectory(dataDirectory);
        File.WriteAllText(_path, JsonSerializer.Serialize(new Stored(Convert.ToBase64String(salt), Convert.ToBase64String(hash), Iterations)));
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(_path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    public async Task<bool> VerifyAsync(string password)
    {
        int failures;
        lock (_lock) failures = _recentFailures;
        // Each wrong guess makes the next one slower, which blunts password guessing without locking the owner out.
        if (failures > 0) await Task.Delay(TimeSpan.FromSeconds(Math.Min(failures, 8)));

        var stored = JsonSerializer.Deserialize<Stored>(await File.ReadAllTextAsync(_path))!;
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, Convert.FromBase64String(stored.Salt), stored.Iterations, HashAlgorithmName.SHA256, 32);
        var ok = CryptographicOperations.FixedTimeEquals(hash, Convert.FromBase64String(stored.Hash));
        lock (_lock) _recentFailures = ok ? 0 : _recentFailures + 1;
        return ok;
    }
}
