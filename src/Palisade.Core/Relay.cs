using System.Text.Json;

namespace Palisade.Core;

/// <summary>A device that tried to reach a connection-sharing service, how often, and when it last did.</summary>
public sealed class RelaySighting
{
    public string Mac { get; set; } = "";
    public long Attempts { get; set; }
    public DateTimeOffset LastSeen { get; set; }
}

/// <summary>
/// How devices that carry relay software are caught. The name server answers every relay name with one
/// address that leads nowhere; the firewall refuses anything sent there and counts which device sent it.
/// No lookups are logged: the only thing recorded is "this device tried".
/// </summary>
public static class RelayPlan
{
    /// <summary>An address set aside for documentation, so no real service ever lives at it.</summary>
    public const string TrapAddress = "192.0.2.1";
    public const string SeenSet = "relay_seen";

    /// <summary>Reads the counted set from "nft -j list set": hardware address to packets seen.</summary>
    public static Dictionary<string, long> ParseSeen(string json)
    {
        var result = new Dictionary<string, long>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("nftables", out var items)) return result;
            foreach (var item in items.EnumerateArray())
            {
                if (!item.TryGetProperty("set", out var set) || !set.TryGetProperty("elem", out var elems)) continue;
                foreach (var wrapped in elems.EnumerateArray())
                {
                    if (wrapped.ValueKind != JsonValueKind.Object || !wrapped.TryGetProperty("elem", out var elem)) continue;
                    if (!elem.TryGetProperty("val", out var val) || val.ValueKind != JsonValueKind.String) continue;
                    if (!ConfigValidator.TryNormalizeMac(val.GetString(), out var mac)) continue;
                    if (elem.TryGetProperty("counter", out var counter) && counter.TryGetProperty("packets", out var packets) && packets.TryGetInt64(out var count))
                        result[mac] = count;
                }
            }
        }
        catch (JsonException)
        {
        }
        return result;
    }
}

/// <summary>
/// Remembers which devices tried, across rule reloads and restarts. The kernel's counters start again
/// from zero whenever the rules are reloaded, so only growth between two readings is added.
/// </summary>
public sealed class RelayTracker(IEnumerable<RelaySighting>? saved = null)
{
    public static readonly TimeSpan Kept = TimeSpan.FromDays(7);

    private readonly Dictionary<string, RelaySighting> _seen = (saved ?? []).Where(s => ConfigValidator.TryNormalizeMac(s.Mac, out var m) && m == s.Mac).ToDictionary(s => s.Mac);
    private readonly Dictionary<string, long> _last = [];

    /// <summary>Returns true when something new was seen or something old was forgotten, so the caller knows to save.</summary>
    public bool Record(DateTimeOffset now, IReadOnlyDictionary<string, long> counters)
    {
        var changed = false;
        foreach (var (mac, raw) in counters)
        {
            var before = _last.GetValueOrDefault(mac);
            var growth = raw >= before ? raw - before : raw;
            _last[mac] = raw;
            if (growth == 0) continue;
            if (!_seen.TryGetValue(mac, out var sighting)) _seen[mac] = sighting = new RelaySighting { Mac = mac };
            sighting.Attempts += growth;
            sighting.LastSeen = now;
            changed = true;
        }
        foreach (var mac in _last.Keys.Where(m => !counters.ContainsKey(m)).ToList()) _last.Remove(mac);
        foreach (var old in _seen.Values.Where(s => now - s.LastSeen > Kept).ToList())
        {
            _seen.Remove(old.Mac);
            changed = true;
        }
        return changed;
    }

    public List<RelaySighting> Report() =>
        [.. _seen.Values.OrderByDescending(s => s.LastSeen).Select(s => new RelaySighting { Mac = s.Mac, Attempts = s.Attempts, LastSeen = s.LastSeen })];
}
