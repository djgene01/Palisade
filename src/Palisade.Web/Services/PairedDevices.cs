using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Palisade.Web.Services;

/// <summary>A phone or tablet allowed to use the companion app's interface. The token itself is never kept.</summary>
public sealed record PairedDevice(string Id, string Name, DateTimeOffset PairedAt, DateTimeOffset LastSeen);

/// <summary>A code shown on the Advanced page, waiting to be typed or scanned into the app.</summary>
public sealed record PairingCode(string Code, DateTimeOffset ExpiresAt);

/// <summary>
/// Pairing codes and the devices they let in. A code is short so it can be typed, which is safe because it
/// lives for minutes, works once, and a few wrong guesses throw it away. What a device receives in return
/// is a long random token; only its hash is stored, so the file on disk cannot be used to get in.
/// </summary>
public sealed class PairedDevices
{
    public static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(5);
    public const int MaxDevices = 20;
    public const int MaxNameLength = 40;
    private const int WrongGuessesAllowed = 5;
    // Crockford's base32 without the letters people misread (I, L, O, U): 40 bits in 8 characters.
    private const string CodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private static readonly TimeSpan LastSeenResolution = TimeSpan.FromMinutes(10);

    private sealed record Stored(string Id, string Name, string TokenHash, DateTimeOffset PairedAt, DateTimeOffset LastSeen);

    private readonly string _path;
    private readonly TimeProvider _clock;
    private readonly Lock _lock = new();
    private readonly List<Stored> _devices;
    private PairingCode? _code;
    private int _wrongGuesses;

    public PairedDevices(string dataDirectory, TimeProvider clock)
    {
        _path = Path.Combine(dataDirectory, "devices.json");
        _clock = clock;
        _devices = File.Exists(_path) ? JsonSerializer.Deserialize<List<Stored>>(File.ReadAllText(_path)) ?? [] : [];
    }

    /// <summary>Raised when the list of devices or the waiting code changes, so open pages can refresh.</summary>
    public event Action? Changed;

    public IReadOnlyList<PairedDevice> Devices
    {
        get { lock (_lock) return [.. _devices.Select(d => new PairedDevice(d.Id, d.Name, d.PairedAt, d.LastSeen))]; }
    }

    /// <summary>The code waiting to be used, or null when there is none or it ran out.</summary>
    public PairingCode? WaitingCode
    {
        get { lock (_lock) return _code is { } c && c.ExpiresAt > _clock.GetUtcNow() ? c : null; }
    }

    /// <summary>Starts pairing. Any earlier code stops working, so only the newest one on screen counts.</summary>
    public PairingCode NewCode()
    {
        var chars = RandomNumberGenerator.GetItems<char>(CodeAlphabet, 8);
        var code = new PairingCode(new string(chars), _clock.GetUtcNow() + CodeLifetime);
        lock (_lock)
        {
            _code = code;
            _wrongGuesses = 0;
        }
        Changed?.Invoke();
        return code;
    }

    public void CancelCode()
    {
        lock (_lock) _code = null;
        Changed?.Invoke();
    }

    /// <summary>
    /// Trades a code for a token. Returns null and a reason in plain words when the code is wrong, used or
    /// out of time. The code may be typed with or without its dash, in either case.
    /// </summary>
    public (string? Token, PairedDevice? Device, string Problem) Pair(string? code, string? name)
    {
        var typed = (code ?? "").Replace("-", "").Replace(" ", "").Trim().ToUpperInvariant();
        var label = CleanName(name);
        string token;
        Stored stored;
        lock (_lock)
        {
            var now = _clock.GetUtcNow();
            if (_code is null || _code.ExpiresAt <= now)
                return (null, null, "There is no pairing code waiting. Open Advanced on the firewall's page and choose Link a phone.");
            // Hashing both sides gives equal lengths, so the comparison takes the same time however close a guess is.
            if (!CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(Encoding.UTF8.GetBytes(typed)), SHA256.HashData(Encoding.UTF8.GetBytes(_code.Code))))
            {
                if (++_wrongGuesses >= WrongGuessesAllowed) _code = null;
                return (null, null, _code is null
                    ? "That code was wrong too many times, so it no longer works. Make a new one on the firewall's page."
                    : "That code is not the one on the firewall's page. Check it and try again.");
            }
            if (_devices.Count >= MaxDevices)
                return (null, null, $"{MaxDevices} devices are already linked. Remove one on the firewall's Advanced page first.");

            _code = null;
            token = Base64Url(RandomNumberGenerator.GetBytes(32));
            stored = new Stored(NewId(), label, Hash(token), now, now);
            _devices.Add(stored);
            SaveLocked();
        }
        Changed?.Invoke();
        return (token, new PairedDevice(stored.Id, stored.Name, stored.PairedAt, stored.LastSeen), "");
    }

    /// <summary>The device a token belongs to, or null. Notes when it was last seen, without writing to disk on every request.</summary>
    public PairedDevice? Verify(string? token)
    {
        if (string.IsNullOrEmpty(token) || token.Length > 100) return null;
        var hash = Convert.FromBase64String(Hash(token));
        lock (_lock)
        {
            var index = _devices.FindIndex(d => CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(d.TokenHash), hash));
            if (index < 0) return null;
            var device = _devices[index];
            var now = _clock.GetUtcNow();
            if (now - device.LastSeen >= LastSeenResolution)
            {
                _devices[index] = device = device with { LastSeen = now };
                SaveLocked();
            }
            return new PairedDevice(device.Id, device.Name, device.PairedAt, device.LastSeen);
        }
    }

    /// <summary>Takes a device's access away. Its token stops working at once.</summary>
    public bool Remove(string id)
    {
        bool removed;
        lock (_lock)
        {
            removed = _devices.RemoveAll(d => d.Id == id) > 0;
            if (removed) SaveLocked();
        }
        if (removed) Changed?.Invoke();
        return removed;
    }

    /// <summary>Formats a code the way it is shown: two groups of four.</summary>
    public static string Display(string code) => code.Length == 8 ? $"{code[..4]}-{code[4..]}" : code;

    private static string CleanName(string? name)
    {
        var text = new string((name ?? "").Where(ch => !char.IsControl(ch)).ToArray()).Trim();
        if (text.Length > MaxNameLength) text = text[..MaxNameLength].Trim();
        return text.Length == 0 ? "Phone" : text;
    }

    private static string NewId() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(6));

    private static string Hash(string token) => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private void SaveLocked()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var temp = _path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(_devices));
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.Move(temp, _path, overwrite: true);
    }
}
