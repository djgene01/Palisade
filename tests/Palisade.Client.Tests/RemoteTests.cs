using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Palisade.Core;
using Palisade.UI.Services;
using Palisade.Web.Services;

namespace Palisade.Client.Tests;

/// <summary>
/// The real web interface on real ports, with its real certificate, on the simulated network. The client
/// talks to it exactly as the app will, over TLS that it can only accept by its pinned key.
/// </summary>
public sealed class RunningFirewall : WebApplicationFactory<Program>
{
    public string DataDirectory { get; } = Path.Combine(Path.GetTempPath(), "palisade-client-tests", Guid.NewGuid().ToString("N"));
    public int ApiPort { get; } = FreePort();

    public RunningFirewall()
    {
        Environment.SetEnvironmentVariable("STATE_DIRECTORY", DataDirectory);
        Environment.SetEnvironmentVariable("Palisade__Backend", "simulated");
        Environment.SetEnvironmentVariable("Palisade__MakerLookup", "false");
        Environment.SetEnvironmentVariable("Palisade__WebPort", FreePort().ToString());
        Environment.SetEnvironmentVariable("Palisade__CheckPort", FreePort().ToString());
        Environment.SetEnvironmentVariable("Palisade__ApiPort", ApiPort.ToString());
        UseKestrel();
        StartServer();
    }

    public FirewallAddress Address => new("localhost", ApiPort, null);
    public string Pin => Services.GetRequiredService<FirewallCertificate>().Pin;
    public PairedDevices Paired => Services.GetRequiredService<PairedDevices>();

    /// <summary>The link the Advanced page would put in its QR code right now.</summary>
    public string NewPairingLink() => AppContract.PairingLink("localhost", ApiPort, Pin, Paired.NewCode().Code);

    public async Task<FirewallLink> LinkAsync(string name = "Test phone") =>
        await Pairing.PairAsync(PairingLinks.Parse(NewPairingLink())!, name);

    public static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { Directory.Delete(DataDirectory, recursive: true); } catch (IOException) { }
    }
}

[CollectionDefinition("running firewall", DisableParallelization = true)]
public sealed class RunningFirewallCollection;

[Collection("running firewall")]
public sealed class RemoteTests : IDisposable
{
    private readonly RunningFirewall _firewall = new();

    public void Dispose() => _firewall.Dispose();

    [Fact]
    public async Task Introducing_reads_the_firewall_and_the_key_it_really_presents()
    {
        var (info, pin) = await PinnedConnection.IntroduceAsync(_firewall.Address);

        Assert.Equal(new ApiInfo("Palisade", AppContract.Version, "dev"), info);
        Assert.Equal(_firewall.Pin, pin);
    }

    [Fact]
    public async Task Introducing_a_closed_address_says_nothing_answered()
    {
        var ex = await Assert.ThrowsAsync<FirewallException>(() =>
            PinnedConnection.IntroduceAsync(new FirewallAddress("localhost", RunningFirewall.FreePort(), null)));
        Assert.Contains("No Palisade firewall answered", ex.Message);
    }

    [Fact]
    public async Task Scanning_the_code_from_the_page_links_this_device()
    {
        var link = await _firewall.LinkAsync("Kitchen tablet");

        Assert.Equal(_firewall.Pin, link.Pin);
        Assert.Equal("Kitchen tablet", Assert.Single(_firewall.Paired.Devices).Name);
        using var backend = new RemoteBackend(link);
        Assert.True((await backend.GetStatusAsync()).Simulated);
    }

    [Fact]
    public async Task A_look_alike_with_another_key_never_receives_the_code()
    {
        var invite = PairingLinks.Parse(_firewall.NewPairingLink())!;
        var impostor = invite with { Address = invite.Address with { Pin = "jS-jMyCvtjk3oLJ5Y3lJu6pgTlTl0pKG0q-gD3K5Qz0" } };

        var ex = await Assert.ThrowsAsync<FirewallException>(() => Pairing.PairAsync(impostor, "Phone"));
        Assert.Contains("fingerprint is different", ex.Message);
        // The code was never sent, so it is still waiting and still works.
        Assert.NotNull(_firewall.Paired.WaitingCode);
        Assert.NotNull(await Pairing.PairAsync(invite, "Phone"));
    }

    [Fact]
    public async Task A_wrong_code_comes_back_with_the_firewalls_own_words()
    {
        _firewall.Paired.NewCode();
        var ex = await Assert.ThrowsAsync<FirewallException>(() => Pairing.PairAsync(_firewall.Address, _firewall.Pin, "WRONG000", "Phone"));
        Assert.Contains("not the one on the firewall's page", ex.Message);
    }

    [Fact]
    public async Task The_shared_screens_state_saves_and_confirms_through_the_app_connection()
    {
        var link = await _firewall.LinkAsync();
        using var backend = new RemoteBackend(link);
        var state = new FirewallState(backend, new RemoteMakers(backend));
        var probe = new RemoteProbe(link);

        await state.LoadAsync();
        Assert.Null(state.Error);
        Assert.False(state.Config!.SetupComplete);

        var issues = await state.SaveAsync(c =>
        {
            c.WanInterface = state.Status!.Interfaces[0].Name;
            c.LanInterface = state.Status.Interfaces[1].Name;
        });
        Assert.Empty(issues);
        await state.RefreshStatusAsync();
        Assert.NotNull(state.Status!.PendingSecondsLeft);

        // What ApplyGuard does in the app: prove a fresh connection works, then keep the change.
        Assert.True(await probe.CanReachAsync());
        await state.ConfirmAsync();
        await state.LoadAsync();
        Assert.Null(state.Status!.PendingSecondsLeft);
        Assert.True(state.Config!.SetupComplete);
        Assert.NotEmpty(state.Devices());
    }

    [Fact]
    public async Task Zero_trust_is_switched_on_and_a_waiting_device_approved_through_the_app_connection()
    {
        var link = await _firewall.LinkAsync();
        using var backend = new RemoteBackend(link);
        var state = new FirewallState(backend, new RemoteMakers(backend));
        await state.LoadAsync();
        await state.SaveAsync(c =>
        {
            c.WanInterface = state.Status!.Interfaces[0].Name;
            c.LanInterface = state.Status.Interfaces[1].Name;
        });
        await state.ConfirmAsync();

        Assert.Empty(await state.SetZeroTrustAsync(new ZeroTrustRequest { Enabled = true, HoldingAddress = "10.99.0.1", HoldingPrefix = 24 }));
        await state.ConfirmAsync();
        await state.LoadAsync();
        Assert.True(state.Config!.ZeroTrust.Enabled);
        Assert.NotEmpty(state.Config.ZeroTrust.Approved);
        var stranger = Assert.Single(state.Waiting);

        // Approving takes effect at once: nothing waits for confirmation.
        Assert.Empty(await state.ChangeApprovalAsync(ApprovalAction.Approve, stranger.Mac, "Visitor phone"));
        await state.LoadAsync();
        Assert.Null(state.Status!.PendingSecondsLeft);
        Assert.Empty(state.Waiting);
        Assert.Contains(state.Config!.ZeroTrust.Approved, a => a.Mac == stranger.Mac && a.Name == "Visitor phone");

        // A bad address is refused with the firewall's own words.
        var refused = await state.SetZeroTrustAsync(new ZeroTrustRequest { Enabled = true, HoldingAddress = "8.8.8.8", HoldingPrefix = 24 });
        Assert.NotEmpty(refused);
    }

    [Fact]
    public async Task Every_other_call_the_pages_make_works_through_the_app_connection()
    {
        using var backend = new RemoteBackend(await _firewall.LinkAsync());

        Assert.NotNull(await backend.GetLeasesAsync());
        Assert.NotNull(await backend.GetUsageAsync());
        Assert.NotNull(await backend.GetWifiAsync());
        var health = await backend.GetHealthAsync(HealthRange.Week);
        Assert.Equal(HealthRange.Week, health.Range);
        Assert.Empty(health.Problem);
        Assert.NotNull(health.Now);
        Assert.NotEmpty(health.Points);
        var speed = await backend.GetSpeedAsync();
        Assert.Empty(speed.Problem);
        Assert.NotNull(speed.Last);
        Assert.True((await backend.RunSpeedTestAsync()).Running);
        Assert.Equal(60, (await backend.SetSpeedAsync(new SpeedSettingsRequest { Enabled = true, IntervalMinutes = 60 })).Settings.IntervalMinutes);
        Assert.True((await backend.SetNamesAsync([new DeviceName { Mac = "52:54:00:aa:00:01", Name = "Gran's tablet" }])).Ok);
        Assert.Equal("Gran's tablet", Assert.Single((await backend.GetConfigAsync()).Names).Name);
        Assert.True((await backend.SetAccessAsync([])).Ok);
        Assert.True((await backend.FlushDnsAsync()).Ok);
        Assert.NotNull(await backend.WatchAsync(new WatchRequest { Address = "192.168.50.100", Seconds = 1 }));
        Assert.NotNull(await backend.GetUpdateAsync());
        Assert.NotNull(await backend.CheckUpdateAsync(install: false));
        Assert.Equal(["52:54:00:aa:00:01"], (await backend.GetMakersAsync(["52:54:00:aa:00:01"])).Keys);

        var config = await backend.GetConfigAsync();
        config.LanAddress = "not an address";
        var rejected = await backend.ApplyAsync(config);
        Assert.False(rejected.Ok);
        Assert.NotEmpty(rejected.Issues);
    }

    [Fact]
    public async Task A_device_removed_on_the_firewall_is_told_so_in_plain_words()
    {
        var link = await _firewall.LinkAsync("Lost phone");
        _firewall.Paired.Remove(link.DeviceId);

        using var backend = new RemoteBackend(link);
        var ex = await Assert.ThrowsAsync<LinkRemovedException>(() => backend.GetStatusAsync());
        Assert.Contains("not linked", ex.Message);
        // The shared screens show it as they show any unreachable firewall.
        var state = new FirewallState(backend, new RemoteMakers(backend));
        await state.LoadAsync();
        Assert.Contains("not linked", state.Error);
    }

    [Fact]
    public async Task A_device_can_unlink_itself()
    {
        var link = await _firewall.LinkAsync("Old tablet");
        using var backend = new RemoteBackend(link);
        await backend.UnpairAsync();

        Assert.Empty(_firewall.Paired.Devices);
        await Assert.ThrowsAsync<LinkRemovedException>(() => backend.GetStatusAsync());
    }

    [Fact]
    public async Task A_firewall_whose_key_changed_is_refused()
    {
        var link = await _firewall.LinkAsync() with { Pin = "jS-jMyCvtjk3oLJ5Y3lJu6pgTlTl0pKG0q-gD3K5Qz0" };
        using var backend = new RemoteBackend(link);

        var ex = await Assert.ThrowsAsync<FirewallException>(() => backend.GetStatusAsync());
        Assert.Contains("fingerprint has changed", ex.Message);
        Assert.False(await new RemoteProbe(link).CanReachAsync());
    }

    [Fact]
    public async Task The_probe_says_no_when_nothing_answers()
    {
        var link = await _firewall.LinkAsync() with { Port = RunningFirewall.FreePort() };
        Assert.False(await new RemoteProbe(link).CanReachAsync());
        Assert.Equal("", await new RemoteProbe(link).ClientAddressAsync());
    }

    [Fact]
    public async Task After_switching_to_a_firewall_out_of_reach_nothing_of_the_previous_one_is_left_to_save()
    {
        var link = await _firewall.LinkAsync();
        var swappable = new Swappable(new RemoteBackend(link));
        var state = new FirewallState(swappable, new RemoteMakers((RemoteBackend)swappable.Current));
        await state.LoadAsync();
        Assert.NotNull(state.Config);

        // What the app does when another firewall is chosen, here one that does not answer.
        swappable.Current = new RemoteBackend(link with { Port = RunningFirewall.FreePort() });
        state.Reset();
        await state.LoadAsync();

        Assert.Null(state.Config);
        Assert.NotNull(state.Error);
        Assert.Contains("Settings have not loaded yet", Assert.Single(await state.SaveAsync(_ => { })).Message);
    }

    /// <summary>Stands in for the app's switchable firewall: every call goes to whichever backend is current.</summary>
    private sealed class Swappable(IFirewallBackend current) : IFirewallBackend
    {
        public IFirewallBackend Current { get; set; } = current;
        public Task<SystemStatus> GetStatusAsync(CancellationToken ct = default) => Current.GetStatusAsync(ct);
        public Task<FirewallConfig> GetConfigAsync(CancellationToken ct = default) => Current.GetConfigAsync(ct);
        public Task<ApplyResult> ApplyAsync(FirewallConfig config, CancellationToken ct = default) => Current.ApplyAsync(config, ct);
        public Task ConfirmAsync(CancellationToken ct = default) => Current.ConfirmAsync(ct);
        public Task RevertAsync(CancellationToken ct = default) => Current.RevertAsync(ct);
        public Task<IReadOnlyList<DhcpLease>> GetLeasesAsync(CancellationToken ct = default) => Current.GetLeasesAsync(ct);
        public Task<UsageReport> GetUsageAsync(CancellationToken ct = default) => Current.GetUsageAsync(ct);
        public Task<ApplyResult> SetAccessAsync(List<DeviceAccess> access, CancellationToken ct = default) => Current.SetAccessAsync(access, ct);
        public Task<ApplyResult> SetNamesAsync(List<DeviceName> names, CancellationToken ct = default) => Current.SetNamesAsync(names, ct);
        public Task<WifiStatus> GetWifiAsync(CancellationToken ct = default) => Current.GetWifiAsync(ct);
        public Task<ApplyResult> SetWifiAsync(WifiRequest request, CancellationToken ct = default) => Current.SetWifiAsync(request, ct);
        public Task<ApplyResult> SetZeroTrustAsync(ZeroTrustRequest request, CancellationToken ct = default) => Current.SetZeroTrustAsync(request, ct);
        public Task<ApplyResult> ChangeApprovalAsync(ApprovalChange change, CancellationToken ct = default) => Current.ChangeApprovalAsync(change, ct);
    }

    [Fact]
    public async Task A_long_list_of_devices_is_asked_about_in_slices_the_firewall_accepts()
    {
        using var backend = new RemoteBackend(await _firewall.LinkAsync());
        var macs = Enumerable.Range(0, 250).Select(i => $"52:54:00:aa:{i / 256:x2}:{i % 256:x2}").ToList();

        var answers = await backend.GetMakersAsync(macs);
        Assert.Equal(250, answers.Count);
    }

    [Fact]
    public void Tokens_never_show_up_when_a_link_is_written_out()
    {
        var link = new FirewallLink("192.168.50.1", 8443, "pin", "very-secret-token", "abc123");
        Assert.DoesNotContain("very-secret-token", link.ToString());
        Assert.DoesNotContain("very-secret-token", new PairResponse("abc123", "very-secret-token").ToString());
    }

    [Fact]
    public async Task Makers_are_answered_at_once_and_fetched_in_the_background()
    {
        using var backend = new RemoteBackend(await _firewall.LinkAsync());
        var makers = new RemoteMakers(backend);

        // The demo firewall looks nothing up, so the answer stays "not known", and asking never throws or blocks.
        Assert.Null(makers.Find("52:54:00:aa:00:01"));
        await Task.Delay(500);
        Assert.Null(makers.Find("52:54:00:aa:00:01"));
    }
}
