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
    /// <summary>
    /// Makes Zero Trust's lists the live ones, at once and without reloading the rules: the approved set, the
    /// address server's hosts file, and the saved rules that load at boot. <paramref name="live"/> is the
    /// config in force right now, waiting for confirmation or not.
    /// </summary>
    Task SetApprovalsAsync(FirewallConfig live, CancellationToken ct);
    /// <summary>Hardware addresses the home network port has heard from lately, including devices with addresses set by hand.</summary>
    Task<IReadOnlyList<string>> GetNeighboursAsync(FirewallConfig live, CancellationToken ct);
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
            // Zero Trust is changed only through its own calls. An app or page from before it existed sends no
            // such section, and one with an older copy would undo approvals made since: neither may touch it.
            config.ZeroTrust = current.ZeroTrust;
            return await ApplyLockedAsync(config, ct);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Checks, applies and starts the wait for confirmation. The caller holds the gate.</summary>
    private async Task<ApplyResult> ApplyLockedAsync(FirewallConfig config, CancellationToken ct)
    {
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

    public async Task<ApplyResult> SetZeroTrustAsync(ZeroTrustRequest request, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var config = (_pending ?? _active).Clone();
            config.SetupComplete = true;
            var turningOn = request.Enabled && !config.ZeroTrust.Enabled;
            config.ZeroTrust.Enabled = request.Enabled;
            // Switching off keeps the holding zone as it was, so {"enabled":false} alone is enough at the console.
            if (request.Enabled)
                (config.ZeroTrust.HoldingAddress, config.ZeroTrust.HoldingPrefix) = (request.HoldingAddress.Trim(), request.HoldingPrefix);
            if (turningOn)
            {
                // Everything already here is let in, so switching the mode on cuts nobody in the house off.
                var leases = await platform.GetLeasesAsync(ct);
                var neighbours = await platform.GetNeighboursAsync(config, ct);
                config.ZeroTrust.Approved = ZeroTrustPlan.KnownDevices(config, leases, neighbours, DateTimeOffset.UtcNow);
            }
            return await ApplyLockedAsync(config, ct);
        }
        finally { _gate.Release(); }
    }

    public async Task<ApplyResult> ChangeApprovalAsync(ApprovalChange change, CancellationToken ct = default)
    {
        if (!ConfigValidator.TryNormalizeMac(change.Mac, out var mac))
            return ApplyResult.Failed($"\"{change.Mac}\" is not a valid hardware (MAC) address.");
        var name = (change.Name ?? "").Trim();
        if (name.Length > 0 && !ConfigValidator.IsSafeName(name))
            return ApplyResult.Failed("Give the device a short name using letters, numbers and spaces.");
        await _gate.WaitAsync(ct);
        try
        {
            var live = _pending ?? _active;
            if (!live.ZeroTrust.Enabled) return ApplyResult.Failed("Zero Trust Mode is off, so there is nothing to approve.");
            var approved = live.ZeroTrust.Approved.Any(d => d.Mac == mac);
            var now = DateTimeOffset.UtcNow;

            // Taking access away from an approved device could be this very one: that waits for confirmation.
            if (approved && change.Action is ApprovalAction.Remove or ApprovalAction.Block)
            {
                var config = live.Clone();
                config.ZeroTrust.Approved.RemoveAll(d => d.Mac == mac);
                if (change.Action == ApprovalAction.Block)
                    config.ZeroTrust.Blocked.Add(new BlockedDevice { Mac = mac, Name = name, BlockedAt = now });
                return await ApplyLockedAsync(config, ct);
            }

            // Everything else only lets a device in, or keeps a waiting one out: it takes effect at once.
            void Change(ZeroTrustSettings z)
            {
                switch (change.Action)
                {
                    case ApprovalAction.Approve:
                        z.Blocked.RemoveAll(d => d.Mac == mac);
                        var existing = z.Approved.FirstOrDefault(d => d.Mac == mac);
                        if (existing is null) z.Approved.Add(new ApprovedDevice { Mac = mac, Name = name, ApprovedAt = now });
                        else if (name.Length > 0) existing.Name = name;
                        break;
                    case ApprovalAction.Unblock:
                        z.Blocked.RemoveAll(d => d.Mac == mac);
                        break;
                    case ApprovalAction.Block:
                        if (z.Blocked.All(d => d.Mac != mac)) z.Blocked.Add(new BlockedDevice { Mac = mac, Name = name, BlockedAt = now });
                        break;
                }
            }
            var check = live.Clone();
            Change(check.ZeroTrust);
            var issues = ZeroTrustPlan.Validate(check);
            if (issues.Count > 0) return ApplyResult.Failed(issues);
            Change(_active.ZeroTrust);
            if (_pending is not null) Change(_pending.ZeroTrust);
            if (_active.SetupComplete) await SaveActiveAsync(ct);
            await platform.SetApprovalsAsync(_pending ?? _active, ct);
            return new ApplyResult { Ok = true };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log?.Invoke($"Changing an approval failed: {ex.Message}");
            return ApplyResult.Failed($"The change could not be saved. ({ex.Message})");
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
