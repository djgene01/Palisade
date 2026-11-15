using System.Text.Json;

namespace Palisade.Core;

/// <summary>The only part that differs between a real Debian box and the simulated one.</summary>
public interface ISystemPlatform
{
    /// <summary>Dry-run the generated files. Returns problems in plain text, empty when they are fine.</summary>
    Task<IReadOnlyList<string>> CheckAsync(FirewallConfig config, GeneratedFiles files, CancellationToken ct);
    Task ApplyAsync(FirewallConfig config, GeneratedFiles files, CancellationToken ct);
    /// <summary>Return to the state before first setup: no filtering, no DHCP.</summary>
    Task ClearAsync(CancellationToken ct);
    Task<SystemStatus> GetStatusAsync(FirewallConfig active, CancellationToken ct);
    Task<IReadOnlyList<DhcpLease>> GetLeasesAsync(CancellationToken ct);
    /// <summary>Internet use per home-network address over the last 24 hours, busiest first.</summary>
    Task<UsageReport> GetUsageAsync(CancellationToken ct);
    /// <summary>Makes the pauses and schedules the ones the clock is checked against, starting now.</summary>
    Task SetAccessAsync(IReadOnlyList<DeviceAccess> access, CancellationToken ct);
    Task<WifiStatus> GetWifiAsync(CancellationToken ct);
    Task<ApplyResult> SetWifiAsync(WifiRequest request, CancellationToken ct);
}

/// <summary>
/// Owns the saved config and the apply, confirm, undo cycle. A change goes live immediately but is only
/// saved once confirmed; if nobody confirms in time the previous config is put back, so a bad change
/// cannot lock the owner out for good.
/// </summary>
public sealed class FirewallEngine(ISystemPlatform platform, string dataDirectory, TimeSpan confirmWindow, Action<string>? log = null)
    : IFirewallBackend, IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _configPath = Path.Combine(dataDirectory, "config.json");
    private FirewallConfig _active = new();
    private FirewallConfig? _pending;
    private DateTimeOffset _deadline;
    private CancellationTokenSource? _timer;

    public async Task InitializeAsync(CancellationToken ct = default)
    {
        Directory.CreateDirectory(dataDirectory);
        if (File.Exists(_configPath))
        {
            try
            {
                _active = JsonSerializer.Deserialize<FirewallConfig>(await File.ReadAllTextAsync(_configPath, ct), PalisadeJson.Options) ?? new();
            }
            catch (JsonException ex)
            {
                log?.Invoke($"Saved config could not be read, starting unconfigured: {ex.Message}");
            }
        }
        if (!_active.SetupComplete) return;
        try
        {
            await platform.ApplyAsync(_active, ConfigRenderer.Render(_active), ct);
        }
        catch (Exception ex)
        {
            log?.Invoke($"Could not apply the saved config at startup: {ex.Message}");
        }
    }

    public async Task<FirewallConfig> GetConfigAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try { return (_pending ?? _active).Clone(); }
        finally { _gate.Release(); }
    }

    public async Task<SystemStatus> GetStatusAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var status = await platform.GetStatusAsync(_pending ?? _active, ct);
            status.PendingSecondsLeft = _pending is null ? null : Math.Max(0, (int)Math.Ceiling((_deadline - DateTimeOffset.UtcNow).TotalSeconds));
            return status;
        }
        finally { _gate.Release(); }
    }

    public Task<IReadOnlyList<DhcpLease>> GetLeasesAsync(CancellationToken ct = default) => platform.GetLeasesAsync(ct);

    public Task<UsageReport> GetUsageAsync(CancellationToken ct = default) => platform.GetUsageAsync(ct);

    public Task<WifiStatus> GetWifiAsync(CancellationToken ct = default) => platform.GetWifiAsync(ct);

    public Task<ApplyResult> SetWifiAsync(WifiRequest request, CancellationToken ct = default)
    {
        var issues = WifiPlan.Validate(request);
        return issues.Count > 0 ? Task.FromResult(ApplyResult.Failed(issues)) : platform.SetWifiAsync(request, ct);
    }

    public async Task<ApplyResult> ApplyAsync(FirewallConfig config, CancellationToken ct = default)
    {
        config = config.Clone();
        config.SetupComplete = true;
        await _gate.WaitAsync(ct);
        try
        {
            // Pauses and schedules have their own save path. A page that loaded its settings before a pause
            // was pressed must not wipe that pause by saving something unrelated.
            var current = (_pending ?? _active).Clone();
            config.Access = current.Access;
            config.Names = current.Names;
            var issues = ConfigValidator.Validate(config);
            if (issues.Count > 0) return ApplyResult.Failed(issues);
            var files = ConfigRenderer.Render(config);

            var problems = await platform.CheckAsync(config, files, ct);
            if (problems.Count > 0) return ApplyResult.Failed(problems.Select(p => new ValidationIssue("", p)));

            try
            {
                await platform.ApplyAsync(config, files, ct);
            }
            catch (Exception ex)
            {
                log?.Invoke($"Apply failed, restoring the previous config: {ex.Message}");
                await RestoreActiveAsync(CancellationToken.None);
                return ApplyResult.Failed($"The change could not be applied, so nothing was changed. ({ex.Message})");
            }

            // A second change while one is pending replaces it; the undo target stays the last confirmed config.
            _pending = config;
            _deadline = DateTimeOffset.UtcNow + confirmWindow;
            StartTimer();
            return new ApplyResult { Ok = true, ConfirmWithinSeconds = (int)confirmWindow.TotalSeconds };
        }
        finally { _gate.Release(); }
    }

    public async Task ConfirmAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            if (_pending is null) return;
            _active = _pending;
            _pending = null;
            _timer?.Cancel();
            await SaveActiveAsync(ct);
        }
        finally { _gate.Release(); }
    }

    public async Task<ApplyResult> SetAccessAsync(List<DeviceAccess> access, CancellationToken ct = default)
    {
        var issues = AccessPlan.Validate(access);
        if (issues.Count > 0) return ApplyResult.Failed(issues);
        await _gate.WaitAsync(ct);
        try
        {
            var copy = new FirewallConfig { Access = access }.Clone().Access;
            _active.Access = copy;
            if (_pending is not null) _pending.Access = new FirewallConfig { Access = access }.Clone().Access;
            if (_active.SetupComplete) await SaveActiveAsync(ct);
            await platform.SetAccessAsync(copy, ct);
            return new ApplyResult { Ok = true };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log?.Invoke($"Saving pauses and schedules failed: {ex.Message}");
            return ApplyResult.Failed($"The change could not be saved. ({ex.Message})");
        }
        finally { _gate.Release(); }
    }

    public async Task<ApplyResult> SetNamesAsync(List<DeviceName> names, CancellationToken ct = default)
    {
        var issues = DeviceName.Validate(names);
        if (issues.Count > 0) return ApplyResult.Failed(issues);
        await _gate.WaitAsync(ct);
        try
        {
            _active.Names = new FirewallConfig { Names = names }.Clone().Names;
            if (_pending is not null) _pending.Names = new FirewallConfig { Names = names }.Clone().Names;
            if (_active.SetupComplete) await SaveActiveAsync(ct);
            return new ApplyResult { Ok = true };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log?.Invoke($"Saving device names failed: {ex.Message}");
            return ApplyResult.Failed($"The name could not be saved. ({ex.Message})");
        }
        finally { _gate.Release(); }
    }

    private async Task SaveActiveAsync(CancellationToken ct)
    {
        var temp = _configPath + ".tmp";
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(_active, PalisadeJson.Options), ct);
        File.Move(temp, _configPath, overwrite: true);
    }

    public async Task RevertAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            if (_pending is null) return;
            _pending = null;
            _timer?.Cancel();
            await RestoreActiveAsync(ct);
        }
        finally { _gate.Release(); }
    }

    private async Task RestoreActiveAsync(CancellationToken ct)
    {
        try
        {
            if (_active.SetupComplete) await platform.ApplyAsync(_active, ConfigRenderer.Render(_active), ct);
            else await platform.ClearAsync(ct);
        }
        catch (Exception ex)
        {
            log?.Invoke($"Restoring the previous config failed: {ex.Message}");
        }
    }

    private void StartTimer()
    {
        _timer?.Cancel();
        var cts = _timer = new CancellationTokenSource();
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(confirmWindow, cts.Token);
                log?.Invoke("Change was not confirmed in time, undoing it.");
                await _gate.WaitAsync(cts.Token);
                try
                {
                    if (_pending is null || cts.IsCancellationRequested) return;
                    _pending = null;
                    await RestoreActiveAsync(CancellationToken.None);
                }
                finally { _gate.Release(); }
            }
            catch (OperationCanceledException) { }
        });
    }

    public void Dispose()
    {
        _timer?.Cancel();
        _gate.Dispose();
    }
}
