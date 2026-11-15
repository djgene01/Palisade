namespace Palisade.Core;

/// <summary>Internet use of one home-network address: totals for the report's period, and the speed right now.</summary>
public sealed record DeviceUsage(string Address, long DownBytes, long UpBytes, double DownRate, double UpRate);

public sealed class UsageReport
{
    /// <summary>When the totals start: 24 hours ago, or when counting began if that is more recent.</summary>
    public DateTimeOffset Since { get; set; }
    public List<DeviceUsage> Devices { get; set; } = [];
}

/// <summary>
/// Turns the kernel's ever-growing per-address byte counters into "how much in the last 24 hours" and
/// "how fast right now". The kernel counters start again from zero whenever the rules are reloaded, so
/// only the growth between two readings is ever trusted.
/// </summary>
public sealed class UsageTracker(DateTimeOffset startedAt)
{
    private sealed class Entry
    {
        public long LastDown, LastUp;
        public double DownRate, UpRate;
        public readonly SortedDictionary<long, (long Down, long Up)> Hours = [];
    }

    private const int HoursKept = 24;
    private readonly Dictionary<string, Entry> _entries = [];
    private DateTimeOffset? _lastAt;

    public DateTimeOffset LastSampleAt => _lastAt ?? DateTimeOffset.MinValue;

    public void Record(DateTimeOffset now, IReadOnlyDictionary<string, (long Down, long Up)> counters)
    {
        var first = _lastAt is null;
        var seconds = first ? 0 : (now - _lastAt!.Value).TotalSeconds;
        var hour = now.ToUnixTimeSeconds() / 3600;

        foreach (var (address, raw) in counters)
        {
            if (!_entries.TryGetValue(address, out var entry))
            {
                // What the kernel counted before this program started watching happened at an unknown
                // time, so it is not added to any hour. An address that shows up later is new traffic.
                _entries[address] = entry = first
                    ? new Entry { LastDown = raw.Down, LastUp = raw.Up }
                    : new Entry();
            }
            var down = Growth(raw.Down, entry.LastDown);
            var up = Growth(raw.Up, entry.LastUp);
            (entry.LastDown, entry.LastUp) = (raw.Down, raw.Up);
            (entry.DownRate, entry.UpRate) = seconds > 0.5 ? (down / seconds, up / seconds) : (0, 0);
            if (down == 0 && up == 0) continue;
            var bucket = entry.Hours.GetValueOrDefault(hour);
            entry.Hours[hour] = (bucket.Down + down, bucket.Up + up);
        }

        foreach (var (address, entry) in _entries.ToList())
        {
            if (!counters.ContainsKey(address))
            {
                // Gone from the kernel's table (idle for a day, or the rules were reloaded): it will count from zero again.
                (entry.LastDown, entry.LastUp, entry.DownRate, entry.UpRate) = (0, 0, 0, 0);
            }
            foreach (var old in entry.Hours.Keys.Where(h => h <= hour - HoursKept).ToList()) entry.Hours.Remove(old);
            if (entry.Hours.Count == 0 && !counters.ContainsKey(address)) _entries.Remove(address);
        }
        _lastAt = now;
    }

    /// <summary>A counter lower than last time means it was reset, so everything it shows is new.</summary>
    private static long Growth(long now, long before) => now >= before ? now - before : now;

    public UsageReport Report(DateTimeOffset now)
    {
        var windowStart = now.AddHours(-HoursKept);
        return new UsageReport
        {
            Since = startedAt > windowStart ? startedAt : windowStart,
            Devices =
            [
                .. _entries
                    .Select(e => new DeviceUsage(e.Key, e.Value.Hours.Values.Sum(h => h.Down), e.Value.Hours.Values.Sum(h => h.Up), e.Value.DownRate, e.Value.UpRate))
                    .Where(d => d.DownBytes + d.UpBytes > 0 || d.DownRate + d.UpRate > 0)
                    .OrderByDescending(d => d.DownBytes + d.UpBytes),
            ],
        };
    }
}

public static class UsageParser
{
    /// <summary>Reads the elements of one counted set from "nft -j list set". Returns address to bytes; empty when the text is not what was expected.</summary>
    public static Dictionary<string, long> ParseSet(string json)
    {
        var result = new Dictionary<string, long>();
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("nftables", out var items)) return result;
            foreach (var item in items.EnumerateArray())
            {
                if (!item.TryGetProperty("set", out var set) || !set.TryGetProperty("elem", out var elems)) continue;
                foreach (var wrapped in elems.EnumerateArray())
                {
                    if (wrapped.ValueKind != System.Text.Json.JsonValueKind.Object || !wrapped.TryGetProperty("elem", out var elem)) continue;
                    if (!elem.TryGetProperty("val", out var val) || val.ValueKind != System.Text.Json.JsonValueKind.String) continue;
                    if (!Ip4.TryParse(val.GetString(), out var ip)) continue;
                    if (elem.TryGetProperty("counter", out var counter) && counter.TryGetProperty("bytes", out var bytes) && bytes.TryGetInt64(out var count))
                        result[ip.ToString()] = count;
                }
            }
        }
        catch (System.Text.Json.JsonException)
        {
        }
        return result;
    }
}
