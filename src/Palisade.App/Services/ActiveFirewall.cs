using Palisade.Client;
using Palisade.Core;
using Palisade.UI.Services;

namespace Palisade.App.Services;

/// <summary>
/// The firewall the screens are showing right now: the demo inside the app, or a linked one over the network.
/// The shared screens are given this one object for every interface they need; switching firewalls swaps
/// what is behind it, and the screens then load afresh.
/// </summary>
public sealed class ActiveFirewall(FirewallEngine demo) : IFirewallBackend, IUpdates, ITrafficWatch, IDnsControl, IConnectionProbe, IMakerSource, ISystemHealth, ISpeedTest
{
    private readonly SimulatedUpdates _demoUpdates = new();
    private readonly Lazy<SimulatedHealth> _demoHealth = new(() => new SimulatedHealth());
    private readonly Lazy<SimulatedSpeedTest> _demoSpeed = new(() => new SimulatedSpeedTest());
    private readonly SimulatedWatch _demoWatch = new();
    private readonly DemoProbe _demoProbe = new();

    private RemoteBackend? _remote;
    private RemoteProbe? _remoteProbe;
    private RemoteMakers? _remoteMakers;

    /// <summary>True when showing the demo; false when showing a linked firewall or nothing.</summary>
    public bool IsDemo { get; private set; }

    /// <summary>The linked firewall shown, or null for the demo or nothing.</summary>
    public FirewallLink? Link => _remote?.Link;

    public bool IsChosen => IsDemo || _remote is not null;

    /// <summary>The line under the name: which firewall this is.</summary>
    public string Name => IsDemo ? "Demo firewall" : Link is { } link ? $"Firewall at {link.Host}" : "No firewall chosen";

    public void ShowDemo()
    {
        Release();
        IsDemo = true;
    }

    public void Show(FirewallLink link)
    {
        Release();
        _remote = new RemoteBackend(link);
        _remoteProbe = new RemoteProbe(link);
        _remoteMakers = new RemoteMakers(_remote);
    }

    public void ShowNothing() => Release();

    private void Release()
    {
        IsDemo = false;
        _remote?.Dispose();
        (_remote, _remoteProbe, _remoteMakers) = (null, null, null);
    }

    private IFirewallBackend Backend => IsDemo ? demo : _remote ?? throw NotChosen();
    private ISpeedTest Speed => IsDemo ? _demoSpeed.Value : _remote ?? throw NotChosen();
    private ISystemHealth Health => IsDemo ? _demoHealth.Value : _remote ?? throw NotChosen();
    private IUpdates Updates => IsDemo ? _demoUpdates : _remote ?? throw NotChosen();
    private ITrafficWatch Watch => IsDemo ? _demoWatch : _remote ?? throw NotChosen();
    private IDnsControl Dns => IsDemo ? _demoWatch : _remote ?? throw NotChosen();

    private static PlainWordsException NotChosen() => new("No firewall is chosen yet. Link one, or try the demo.");

    public Task<SystemStatus> GetStatusAsync(CancellationToken ct = default) => Backend.GetStatusAsync(ct);
    public Task<FirewallConfig> GetConfigAsync(CancellationToken ct = default) => Backend.GetConfigAsync(ct);
    public Task<ApplyResult> ApplyAsync(FirewallConfig config, CancellationToken ct = default) => Backend.ApplyAsync(config, ct);
    public Task ConfirmAsync(CancellationToken ct = default) => Backend.ConfirmAsync(ct);
    public Task RevertAsync(CancellationToken ct = default) => Backend.RevertAsync(ct);
    public Task<IReadOnlyList<DhcpLease>> GetLeasesAsync(CancellationToken ct = default) => Backend.GetLeasesAsync(ct);
    public Task<UsageReport> GetUsageAsync(CancellationToken ct = default) => Backend.GetUsageAsync(ct);
    public Task<ApplyResult> SetAccessAsync(List<DeviceAccess> access, CancellationToken ct = default) => Backend.SetAccessAsync(access, ct);
    public Task<ApplyResult> SetNamesAsync(List<DeviceName> names, CancellationToken ct = default) => Backend.SetNamesAsync(names, ct);
    public Task<WifiStatus> GetWifiAsync(CancellationToken ct = default) => Backend.GetWifiAsync(ct);
    public Task<ApplyResult> SetWifiAsync(WifiRequest request, CancellationToken ct = default) => Backend.SetWifiAsync(request, ct);
    public Task<ApplyResult> SetZeroTrustAsync(ZeroTrustRequest request, CancellationToken ct = default) => Backend.SetZeroTrustAsync(request, ct);
    public Task<ApplyResult> ChangeApprovalAsync(ApprovalChange change, CancellationToken ct = default) => Backend.ChangeApprovalAsync(change, ct);

    public Task<SpeedStatus> GetSpeedAsync(CancellationToken ct = default) => Speed.GetSpeedAsync(ct);
    public Task<SpeedStatus> SetSpeedAsync(SpeedSettingsRequest request, CancellationToken ct = default) => Speed.SetSpeedAsync(request, ct);
    public Task<SpeedStatus> RunSpeedTestAsync(CancellationToken ct = default) => Speed.RunSpeedTestAsync(ct);
    public Task<HealthReport> GetHealthAsync(HealthRange range, CancellationToken ct = default) => Health.GetHealthAsync(range, ct);
    public Task<UpdateStatus> GetUpdateAsync(CancellationToken ct = default) => Updates.GetUpdateAsync(ct);
    public Task<UpdateStatus> SetUpdateAsync(UpdateSettings settings, CancellationToken ct = default) => Updates.SetUpdateAsync(settings, ct);
    public Task<UpdateStatus> CheckUpdateAsync(bool install, CancellationToken ct = default) => Updates.CheckUpdateAsync(install, ct);

    public Task<WatchReport> WatchAsync(WatchRequest request, CancellationToken ct = default) => Watch.WatchAsync(request, ct);
    public Task<ApplyResult> FlushDnsAsync(CancellationToken ct = default) => Dns.FlushDnsAsync(ct);

    public Task<bool> CanReachAsync(CancellationToken ct = default) =>
        IsDemo ? _demoProbe.CanReachAsync(ct) : _remoteProbe?.CanReachAsync(ct) ?? Task.FromResult(false);

    public Task<string> ClientAddressAsync(CancellationToken ct = default) => Task.FromResult("");

    public string? Find(string mac) => IsDemo ? null : _remoteMakers?.Find(mac);
}
