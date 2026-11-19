using System.Text.Json;
using Palisade.Core;

namespace Palisade.Agent;

/// <summary>
/// Reads the machine's processor, memory and disk use every few seconds and keeps the history, saved every few
/// minutes so it survives a restart. Runs from the moment the agent starts, set up or not, and a reading that
/// fails is skipped rather than allowed to stop the loop.
/// </summary>
public sealed class HealthMonitor(string dataDirectory, ILogger<HealthMonitor> log) : ISystemHealth, IAsyncDisposable
{
    private static readonly TimeSpan Every = TimeSpan.FromSeconds(10), SaveEvery = TimeSpan.FromMinutes(5);
    private readonly HealthHistory _history = new();
    private readonly CancellationTokenSource _stop = new();
    private (long Busy, long Total)? _lastCpu;
    private HealthNow? _now;
    private Task? _loop;

    private string HistoryFile => Path.Combine(dataDirectory, "health.json");

    public void Start()
    {
        try
        {
            if (File.Exists(HistoryFile))
                _history.Import(JsonSerializer.Deserialize<List<HealthBucket>>(File.ReadAllText(HistoryFile), PalisadeJson.Options), DateTimeOffset.UtcNow);
        }
        catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException)
        {
            log.LogWarning("The saved processor, memory and disk history could not be read, so it starts afresh: {Error}", e.Message);
        }
        _loop = RunAsync(_stop.Token);
    }

    private async Task RunAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(Every);
        var savedAt = DateTimeOffset.UtcNow;
        do
        {
            try
            {
                Sample(DateTimeOffset.UtcNow);
                if (DateTimeOffset.UtcNow - savedAt >= SaveEvery)
                {
                    await SaveAsync(ct);
                    savedAt = DateTimeOffset.UtcNow;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception e)
            {
                log.LogWarning("Reading processor, memory or disk use failed: {Error}", e.Message);
            }
        }
        while (await WaitAsync(timer, ct));
    }

    private static async Task<bool> WaitAsync(PeriodicTimer timer, CancellationToken ct)
    {
        try { return await timer.WaitForNextTickAsync(ct); }
        catch (OperationCanceledException) { return false; }
    }

    private void Sample(DateTimeOffset now)
    {
        var cpuTimes = HealthParse.CpuTimes(File.ReadAllText("/proc/stat"));
        var cpu = _lastCpu is { } before && cpuTimes is { } after ? HealthParse.CpuPercent(before, after) : null;
        _lastCpu = cpuTimes;
        var memory = HealthParse.Memory(File.ReadAllText("/proc/meminfo")) ?? (0, 0);
        // The same sums as "df": used is everything not free; the share leaves out the blocks kept for root.
        var disk = new DriveInfo("/");
        var diskUsed = disk.TotalSize - disk.TotalFreeSpace;
        var diskPercent = HealthParse.DiskPercent(diskUsed, disk.AvailableFreeSpace);
        var current = new HealthNow
        {
            At = now, CpuPercent = cpu is { } c ? Math.Round(c, 1) : null, Cores = Environment.ProcessorCount,
            Load = File.Exists("/proc/loadavg") ? HealthParse.Load(File.ReadAllText("/proc/loadavg")) : 0,
            MemoryUsed = memory.Used, MemoryTotal = memory.Total,
            DiskUsed = diskUsed, DiskTotal = disk.TotalSize, DiskPercent = Math.Round(diskPercent, 1),
        };
        _now = current;
        _history.Record(now, cpu, current.MemoryPercent, diskPercent);
    }

    private async Task SaveAsync(CancellationToken ct)
    {
        Directory.CreateDirectory(dataDirectory);
        var temp = HistoryFile + ".palisade-tmp";
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(_history.Export(), PalisadeJson.Options), ct);
        File.Move(temp, HistoryFile, overwrite: true);
    }

    public Task<HealthReport> GetHealthAsync(HealthRange range, CancellationToken ct = default)
    {
        var report = _history.Report(range, DateTimeOffset.UtcNow);
        report.Now = _now;
        return Task.FromResult(report);
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        if (_loop is not null) await _loop;
        try { await SaveAsync(CancellationToken.None); }
        catch (Exception e) { log.LogWarning("Saving the processor, memory and disk history failed: {Error}", e.Message); }
        _stop.Dispose();
    }
}
