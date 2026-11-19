using System.Globalization;

namespace Palisade.Core;

/// <summary>How far back the System page looks.</summary>
public enum HealthRange { Hour, Day, Week, Month }

/// <summary>The firewall machine right now.</summary>
public sealed class HealthNow
{
    public DateTimeOffset At { get; set; }
    /// <summary>Share of all processor time in use since the reading before, 0 to 100. Null until two readings exist.</summary>
    public double? CpuPercent { get; set; }
    public int Cores { get; set; }
    /// <summary>The average number of programs waiting to run over the last minute, as "uptime" shows it.</summary>
    public double Load { get; set; }
    /// <summary>Memory in use: everything except what Linux could hand out at once (MemAvailable), in bytes.</summary>
    public long MemoryUsed { get; set; }
    public long MemoryTotal { get; set; }
    /// <summary>The system disk (/), counted the way "df" counts it.</summary>
    public long DiskUsed { get; set; }
    public long DiskTotal { get; set; }
    public double DiskPercent { get; set; }

    public double MemoryPercent => MemoryTotal > 0 ? 100.0 * MemoryUsed / MemoryTotal : 0;
}

/// <summary>
/// One stretch of history, starting at <see cref="At"/> (Unix seconds). Percentages from 0 to 100.
/// Cpu is null when no processor reading fell in the stretch.
/// </summary>
public sealed record HealthPoint(long At, double? Cpu, double? CpuPeak, double Memory, double Disk);

public sealed class HealthReport
{
    public HealthRange Range { get; set; }
    /// <summary>The length of each point, in seconds. Points further apart than this have a gap between them.</summary>
    public int Step { get; set; }
    public DateTimeOffset From { get; set; }
    public DateTimeOffset To { get; set; }
    public HealthNow? Now { get; set; }
    /// <summary>Why there is nothing to show, in plain words, such as a firewall too old to measure itself. Empty when all is well.</summary>
    public string Problem { get; set; } = "";
    /// <summary>Oldest first. Only stretches with readings are listed: the firewall was off or restarting in between.</summary>
    public List<HealthPoint> Points { get; set; } = [];
}

/// <summary>Processor, memory and disk use of the firewall machine, now and over time.</summary>
public interface ISystemHealth
{
    Task<HealthReport> GetHealthAsync(HealthRange range, CancellationToken ct = default);
}

/// <summary>Reads the text Linux offers in /proc. Pure, so it is tested with real captured text.</summary>
public static class HealthParse
{
    /// <summary>
    /// Busy and total processor time from the first ("cpu") line of /proc/stat, in clock ticks. Waiting for the
    /// disk (iowait) counts as idle, like "top" does. Guest time is already part of user time, so it is left out.
    /// </summary>
    public static (long Busy, long Total)? CpuTimes(string procStat)
    {
        var line = procStat.Split('\n').FirstOrDefault(l => l.StartsWith("cpu ", StringComparison.Ordinal));
        if (line is null) return null;
        var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1).Take(8).ToArray();
        if (fields.Length < 4) return null;
        var values = new long[fields.Length];
        for (var i = 0; i < fields.Length; i++)
            if (!long.TryParse(fields[i], NumberStyles.None, CultureInfo.InvariantCulture, out values[i])) return null;
        var idle = values[3] + (values.Length > 4 ? values[4] : 0);
        var total = values.Sum();
        return (total - idle, total);
    }

    /// <summary>The share of processor time in use between two readings, or null when the counters went backwards or did not move.</summary>
    public static double? CpuPercent((long Busy, long Total) before, (long Busy, long Total) after)
    {
        var total = after.Total - before.Total;
        var busy = after.Busy - before.Busy;
        if (total <= 0 || busy < 0) return null;
        return Math.Clamp(100.0 * busy / total, 0, 100);
    }

    /// <summary>Memory in use and in total, in bytes, from /proc/meminfo.</summary>
    public static (long Used, long Total)? Memory(string meminfo)
    {
        var values = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var line in meminfo.Split('\n'))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            var number = line[(colon + 1)..].Trim().Split(' ')[0];
            if (long.TryParse(number, NumberStyles.None, CultureInfo.InvariantCulture, out var kb)) values[line[..colon]] = kb * 1024;
        }
        if (!values.TryGetValue("MemTotal", out var total) || total <= 0) return null;
        // MemAvailable is what can be handed out without swapping; kernels older than 3.14 lack it.
        var available = values.TryGetValue("MemAvailable", out var a)
            ? a
            : values.GetValueOrDefault("MemFree") + values.GetValueOrDefault("Buffers") + values.GetValueOrDefault("Cached");
        return (Math.Clamp(total - available, 0, total), total);
    }

    /// <summary>The first number of /proc/loadavg.</summary>
    public static double Load(string loadavg) =>
        double.TryParse(loadavg.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault(), NumberStyles.Float, CultureInfo.InvariantCulture, out var load) ? load : 0;

    /// <summary>
    /// Used share of a disk the way "df" shows it: used against used plus what ordinary programs may still
    /// write. The blocks kept back for root are left out, so a full disk reads 100%.
    /// </summary>
    public static double DiskPercent(long used, long available) =>
        used + available > 0 ? Math.Clamp(100.0 * used / (used + available), 0, 100) : 0;
}

/// <summary>One stretch of history as saved to disk.</summary>
public sealed record HealthBucket(int Size, long At, int Count, int CpuCount, double CpuSum, double CpuPeak, double MemorySum, double Disk);

/// <summary>
/// Keeps processor, memory and disk use over time: minutes for a day, quarter hours for a month. Readings are
/// averaged into their stretch, with the busiest processor reading kept too, since a short peak is what
/// someone looking at a slow network wants to see.
/// </summary>
public sealed class HealthHistory
{
    public const int Fine = 60, Coarse = 900;
    public static readonly TimeSpan FineKept = TimeSpan.FromDays(1), CoarseKept = TimeSpan.FromDays(31);

    private sealed class Bucket
    {
        public int Count, CpuCount;
        public double CpuSum, CpuPeak, MemorySum, Disk;

        public void Add(double? cpu, double memory, double disk)
        {
            Count++;
            MemorySum += memory;
            Disk = disk;
            if (cpu is not { } c) return;
            CpuCount++;
            CpuSum += c;
            CpuPeak = Math.Max(CpuPeak, c);
        }
    }

    private readonly SortedDictionary<long, Bucket> _fine = [], _coarse = [];
    private readonly Lock _gate = new();

    public void Record(DateTimeOffset now, double? cpu, double memoryPercent, double diskPercent)
    {
        var at = now.ToUnixTimeSeconds();
        lock (_gate)
        {
            Prune(at);
            Add(_fine, at - at % Fine, cpu, memoryPercent, diskPercent);
            Add(_coarse, at - at % Coarse, cpu, memoryPercent, diskPercent);
        }
    }

    private static void Add(SortedDictionary<long, Bucket> buckets, long at, double? cpu, double memory, double disk)
    {
        if (!buckets.TryGetValue(at, out var bucket)) buckets[at] = bucket = new Bucket();
        bucket.Add(cpu, memory, disk);
    }

    /// <summary>
    /// Forgets what is too old, and what lies in the future. A machine without a battery for its clock starts with
    /// the wrong time and jumps when it learns the right one; readings from either side of a jump must not mix.
    /// </summary>
    private void Prune(long now)
    {
        var wentBack = now < _latest;
        _latest = now;
        foreach (var (buckets, size, kept) in new[] { (_fine, Fine, FineKept), (_coarse, Coarse, CoarseKept) })
        {
            var oldest = now - (long)kept.TotalSeconds;
            // Readings arrive in order, so normally only the oldest few need to go.
            while (buckets.Count > 0 && buckets.Keys.First() is var first && first < oldest) buckets.Remove(first);
            if (!wentBack) continue;
            var newest = now - now % size;
            foreach (var at in buckets.Keys.Where(k => k > newest).ToList()) buckets.Remove(at);
        }
    }

    // The latest time seen, to notice the clock going backwards. Starts in the far future so the first call sweeps.
    private long _latest = long.MaxValue;

    public HealthReport Report(HealthRange range, DateTimeOffset now)
    {
        // Each range is shown as a few hundred points at most: an hour of minutes, a day of 5 minutes,
        // a week of hours and a month of 3 hours.
        var (source, span, step) = range switch
        {
            HealthRange.Hour => (_fine, TimeSpan.FromHours(1), Fine),
            HealthRange.Day => (_fine, TimeSpan.FromDays(1), 5 * 60),
            HealthRange.Week => (_coarse, TimeSpan.FromDays(7), 3600),
            _ => (_coarse, TimeSpan.FromDays(30), 3 * 3600),
        };
        var to = now.ToUnixTimeSeconds();
        var from = to - (long)span.TotalSeconds;
        var report = new HealthReport { Range = range, Step = step, From = DateTimeOffset.FromUnixTimeSeconds(from), To = now };
        lock (_gate)
        {
            foreach (var group in source.Where(b => b.Key >= from - from % step && b.Key <= to).GroupBy(b => b.Key - b.Key % step))
            {
                var parts = group.Select(g => g.Value).ToList();
                var count = parts.Sum(p => p.Count);
                var cpuCount = parts.Sum(p => p.CpuCount);
                report.Points.Add(new HealthPoint(group.Key,
                    cpuCount > 0 ? Math.Round(parts.Sum(p => p.CpuSum) / cpuCount, 1) : null,
                    cpuCount > 0 ? Math.Round(parts.Max(p => p.CpuPeak), 1) : null,
                    Math.Round(parts.Sum(p => p.MemorySum) / count, 1),
                    Math.Round(parts[^1].Disk, 1)));
            }
        }
        return report;
    }

    public List<HealthBucket> Export()
    {
        lock (_gate)
            return [.. _fine.Select(b => Saved(Fine, b)).Concat(_coarse.Select(b => Saved(Coarse, b)))];

        static HealthBucket Saved(int size, KeyValuePair<long, Bucket> b) =>
            new(size, b.Key, b.Value.Count, b.Value.CpuCount, b.Value.CpuSum, b.Value.CpuPeak, b.Value.MemorySum, b.Value.Disk);
    }

    /// <summary>Takes back what <see cref="Export"/> saved. Anything that doesn't add up is skipped rather than trusted.</summary>
    public void Import(IEnumerable<HealthBucket>? saved, DateTimeOffset now)
    {
        lock (_gate)
        {
            foreach (var b in saved ?? [])
            {
                var buckets = b.Size switch { Fine => _fine, Coarse => _coarse, _ => null };
                if (buckets is null || b.At % b.Size != 0 || b.Count <= 0 || b.CpuCount < 0 || b.CpuCount > b.Count) continue;
                if (!Valid(b.CpuSum, b.CpuCount * 100.0) || !Valid(b.CpuPeak, 100) || !Valid(b.MemorySum, b.Count * 100.0) || !Valid(b.Disk, 100)) continue;
                buckets[b.At] = new Bucket { Count = b.Count, CpuCount = b.CpuCount, CpuSum = b.CpuSum, CpuPeak = b.CpuPeak, MemorySum = b.MemorySum, Disk = b.Disk };
            }
            Prune(now.ToUnixTimeSeconds());
        }

        static bool Valid(double value, double max) => double.IsFinite(value) && value >= 0 && value <= max + 0.001;
    }
}
