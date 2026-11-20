using System.Net.Http.Json;
using Palisade.Core;

namespace Palisade.Client;

/// <summary>
/// A linked firewall, seen through its app interface. It offers the shared screens the same four interfaces
/// the web interface's agent client offers them, so every page works unchanged; only the road differs.
/// Failures come back as <see cref="FirewallException"/> in words the pages can show as they are.
/// </summary>
public sealed class RemoteBackend : IFirewallBackend, IUpdates, ITrafficWatch, IDnsControl, ISystemHealth, ISpeedTest, IDisposable
{
    // Short for reads and saves, so a firewall out of reach is reported quickly. The agent itself allows a
    // change up to a minute; installing an update can download for minutes on a slow line.
    private static readonly TimeSpan Normal = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan Change = TimeSpan.FromSeconds(75);
    private static readonly TimeSpan Install = TimeSpan.FromMinutes(10);

    private readonly HttpClient _http;

    public RemoteBackend(FirewallLink link) => (Link, _http) = (link, PinnedConnection.Client(link.Address, link.Pin, link.Token));

    public FirewallLink Link { get; }

    public Task<SystemStatus> GetStatusAsync(CancellationToken ct = default) => GetAsync<SystemStatus>("status", ct);
    public Task<FirewallConfig> GetConfigAsync(CancellationToken ct = default) => GetAsync<FirewallConfig>("config", ct);
    public async Task<IReadOnlyList<DhcpLease>> GetLeasesAsync(CancellationToken ct = default) => await GetAsync<List<DhcpLease>>("leases", ct);
    public Task<UsageReport> GetUsageAsync(CancellationToken ct = default) => GetAsync<UsageReport>("usage", ct);
    public Task<WifiStatus> GetWifiAsync(CancellationToken ct = default) => GetAsync<WifiStatus>("wifi", ct);
    public Task<UpdateStatus> GetUpdateAsync(CancellationToken ct = default) => GetAsync<UpdateStatus>("update", ct);

    public Task<ApplyResult> ApplyAsync(FirewallConfig config, CancellationToken ct = default) => PostAsync<ApplyResult>("config/apply", config, Change, ct);
    public Task ConfirmAsync(CancellationToken ct = default) => PostAsync<object>("config/confirm", null, Normal, ct);
    public Task RevertAsync(CancellationToken ct = default) => PostAsync<object>("config/revert", null, Change, ct);
    public Task<ApplyResult> SetAccessAsync(List<DeviceAccess> access, CancellationToken ct = default) => PostAsync<ApplyResult>("access", access, Normal, ct);
    public Task<ApplyResult> SetNamesAsync(List<DeviceName> names, CancellationToken ct = default) => PostAsync<ApplyResult>("names", names, Normal, ct);
    // Joining a Wi-Fi network is given 22 seconds by the agent before it steps back.
    public Task<ApplyResult> SetWifiAsync(WifiRequest request, CancellationToken ct = default) => PostAsync<ApplyResult>("wifi", request, Change, ct);
    // A firewall from before Zero Trust Mode does not know these two calls; it is told to update.
    public Task<ApplyResult> SetZeroTrustAsync(ZeroTrustRequest request, CancellationToken ct = default) => NewerAsync(PostAsync<ApplyResult>("zerotrust", request, Change, ct));
    public Task<ApplyResult> ChangeApprovalAsync(ApprovalChange change, CancellationToken ct = default) => NewerAsync(PostAsync<ApplyResult>("approvals", change, Change, ct));

    private const string SpeedTooOld = "This firewall is too old to test the internet speed. Update it from its Advanced page.";

    public Task<SpeedStatus> GetSpeedAsync(CancellationToken ct = default) => SpeedAsync(GetAsync<SpeedStatus>("speed", ct));
    public Task<SpeedStatus> SetSpeedAsync(SpeedSettingsRequest request, CancellationToken ct = default) => SpeedAsync(PostAsync<SpeedStatus>("speed/settings", request, Normal, ct));
    public Task<SpeedStatus> RunSpeedTestAsync(CancellationToken ct = default) => SpeedAsync(PostAsync<SpeedStatus>("speed/run", null, Normal, ct));

    private static async Task<SpeedStatus> SpeedAsync(Task<SpeedStatus> call)
    {
        try { return await call; }
        catch (FirewallException ex) when (ex.Message.Contains("(404", StringComparison.Ordinal)) { return new SpeedStatus { Problem = SpeedTooOld }; }
    }

    public async Task<HealthReport> GetHealthAsync(HealthRange range, CancellationToken ct = default)
    {
        try { return await GetAsync<HealthReport>($"health?range={range}", ct); }
        catch (FirewallException ex) when (ex.Message.Contains("(404", StringComparison.Ordinal))
        {
            return new HealthReport { Range = range, Problem = "This firewall is too old to show its processor, memory and disk. Update it from its Advanced page." };
        }
    }

    private static async Task<ApplyResult> NewerAsync(Task<ApplyResult> call)
    {
        try { return await call; }
        catch (FirewallException ex) when (ex.Message.Contains("(404", StringComparison.Ordinal))
        {
            throw new FirewallException("Zero Trust Mode needs a newer firewall. Update it from its Advanced page, then try again.", ex);
        }
    }
    public Task<ApplyResult> FlushDnsAsync(CancellationToken ct = default) => PostAsync<ApplyResult>("dns/flush", null, Normal, ct);
    public Task<WatchReport> WatchAsync(WatchRequest request, CancellationToken ct = default) =>
        PostAsync<WatchReport>("watch", request, TimeSpan.FromSeconds(Math.Max(request.Seconds, 0)) + Normal, ct);
    public Task<UpdateStatus> SetUpdateAsync(UpdateSettings settings, CancellationToken ct = default) => PostAsync<UpdateStatus>("update/settings", settings, Normal, ct);
    public Task<UpdateStatus> CheckUpdateAsync(bool install, CancellationToken ct = default) =>
        PostAsync<UpdateStatus>(install ? "update/install" : "update/check", null, install ? Install : Change, ct);

    /// <summary>Who made each device, for the hardware addresses given. Unknown ones come back as null.</summary>
    public async Task<Dictionary<string, string?>> GetMakersAsync(IEnumerable<string> macs, CancellationToken ct = default)
    {
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        // In slices, so a long list of devices never makes a request line the firewall would refuse.
        foreach (var slice in macs.Distinct(StringComparer.OrdinalIgnoreCase).Chunk(AppContract.MakersPerRequest))
        {
            var query = string.Join('&', slice.Select(m => "mac=" + Uri.EscapeDataString(m)));
            foreach (var (mac, maker) in await GetAsync<Dictionary<string, string?>>("makers?" + query, ct)) result[mac] = maker;
        }
        return result;
    }

    /// <summary>Asks the firewall to forget this device. Its token stops working there at once.</summary>
    public Task UnpairAsync(CancellationToken ct = default) => PostAsync<object>("unpair", null, Normal, ct);

    private Task<T> GetAsync<T>(string path, CancellationToken ct) =>
        SendAsync<T>(() => new HttpRequestMessage(HttpMethod.Get, $"{AppContract.Prefix}/{path}"), Normal, ct);

    private Task<T> PostAsync<T>(string path, object? body, TimeSpan limit, CancellationToken ct) =>
        SendAsync<T>(() => new HttpRequestMessage(HttpMethod.Post, $"{AppContract.Prefix}/{path}")
        {
            Content = body is null ? null : JsonContent.Create(body, body.GetType(), options: PinnedConnection.Json),
        }, limit, ct);

    private async Task<T> SendAsync<T>(Func<HttpRequestMessage> request, TimeSpan limit, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(limit);
        HttpResponseMessage response;
        try
        {
            using var message = request();
            response = await _http.SendAsync(message, timeout.Token);
        }
        catch (HttpRequestException ex) when (ex.HttpRequestError == HttpRequestError.SecureConnectionError)
        {
            throw new FirewallException("The firewall at this address is not the one this app was linked to: its fingerprint has changed. "
                + "If you replaced or reset the firewall, link this device again.", ex);
        }
        catch (HttpRequestException ex)
        {
            throw new FirewallException($"Can't reach the firewall at {Link.Host}. Are you on your home network?", ex);
        }
        catch (OperationCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new FirewallException($"The firewall at {Link.Host} took too long to answer.", ex);
        }
        using (response)
        {
            await PinnedConnection.EnsureOkAsync(response, ct);
            if (typeof(T) == typeof(object) || response.Content.Headers.ContentLength == 0) return default!;
            return (await response.Content.ReadFromJsonAsync<T>(PinnedConnection.Json, ct))
                ?? throw new FirewallException("The firewall's answer could not be read.");
        }
    }

    public void Dispose() => _http.Dispose();
}
