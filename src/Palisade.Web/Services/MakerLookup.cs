using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;
using Palisade.Core;

namespace Palisade.Web.Services;

/// <summary>
/// Finds out who made a device, by asking maclookup.app about the manufacturer's half of its hardware
/// address. Only those six digits are sent, never the whole address. Answers are kept on disk, so each
/// manufacturer is asked about once. Lookups run in the background: a page never waits for one.
/// </summary>
public sealed class MakerLookup
{
    private static readonly TimeSpan RetryAfter = TimeSpan.FromHours(1);

    private readonly string _path;
    private readonly bool _enabled;
    private readonly HttpClient _http = new() { BaseAddress = new Uri("https://api.maclookup.app/v2/macs/"), Timeout = TimeSpan.FromSeconds(8) };
    // Prefix to company. An empty company means the service knows no manufacturer for it.
    private readonly ConcurrentDictionary<string, string> _known = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _asked = new();
    private readonly Channel<string> _queue = Channel.CreateUnbounded<string>();

    public MakerLookup(string dataDirectory, bool enabled)
    {
        _path = Path.Combine(dataDirectory, "makers.json");
        _enabled = enabled;
        try
        {
            if (File.Exists(_path))
                foreach (var (prefix, company) in JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(_path)) ?? [])
                    _known[prefix] = Maker.Clean(company);
        }
        catch (Exception) { /* A damaged file only means asking again. */ }
        if (enabled) _ = Task.Run(WorkAsync);
    }

    /// <summary>The maker if it is already known. Otherwise null, and the question is queued for the background.</summary>
    public string? Find(string mac)
    {
        if (Maker.Prefix(mac) is not { } prefix || Maker.IsMadeUp(mac)) return null;
        if (_known.TryGetValue(prefix, out var company)) return company.Length > 0 ? company : null;
        var now = DateTimeOffset.UtcNow;
        if (_enabled && (!_asked.TryGetValue(prefix, out var at) || now - at > RetryAfter))
        {
            _asked[prefix] = now;
            _queue.Writer.TryWrite(prefix);
        }
        return null;
    }

    private async Task WorkAsync()
    {
        await foreach (var prefix in _queue.Reader.ReadAllAsync())
        {
            try
            {
                using var answer = JsonDocument.Parse(await _http.GetStringAsync(prefix));
                var root = answer.RootElement;
                if (root.TryGetProperty("success", out var ok) && ok.ValueKind == JsonValueKind.True)
                {
                    var found = root.TryGetProperty("found", out var f) && f.ValueKind == JsonValueKind.True;
                    _known[prefix] = found && root.TryGetProperty("company", out var c) ? Maker.Clean(c.GetString()) : "";
                    var temp = _path + ".tmp";
                    await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(_known.ToDictionary(), PalisadeJson.Options));
                    File.Move(temp, _path, overwrite: true);
                }
            }
            catch (Exception) { /* No internet or a busy service: Find asks again after an hour. */ }
            // The service allows two questions a second without an account. Stay well under it.
            await Task.Delay(TimeSpan.FromSeconds(1));
        }
    }
}
