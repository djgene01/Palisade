using System.Text.Json;
using Palisade.Core;

namespace Palisade.Core.Tests;

public class VpnTests
{
    private const string Key1 = "q0A2bXn0eWQqW7J0yP1m2rBfV+0d7cNw1n9oKk5r2Gg=", Key2 = "hT7xVq3aB9mN2pR5sK8wY1zC4eF6gH0jL3oQ7uX9vEs=";
    private static readonly DateTimeOffset Now = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);

    private static FirewallConfig On(params VpnDevice[] devices) => new()
    {
        SetupComplete = true, WanInterface = "enp1s0", LanInterface = "enp2s0",
        Vpn = { Enabled = true, Devices = [.. devices] },
    };

    private static VpnDevice Phone(string key = Key1, string address = "10.66.0.2", VpnAccess access = VpnAccess.HomeAndInternet) =>
        new() { Name = "Annas phone", PublicKey = key, Address = address, Access = access };

    [Theory]
    [InlineData("41.193.12.57", true)]
    [InlineData("102.182.43.147", true)]
    [InlineData("192.168.1.10", false)]
    [InlineData("10.0.0.57", false)]
    [InlineData("172.20.1.1", false)]
    [InlineData("100.64.1.1", false)]       // carrier-grade NAT
    [InlineData("100.127.255.254", false)]
    [InlineData("100.128.0.1", true)]
    [InlineData("169.254.3.4", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("198.51.100.7", false)]
    [InlineData("224.0.0.1", false)]
    public void Only_a_real_internet_address_counts_as_public(string address, bool expected)
    {
        Assert.True(Ip4.TryParse(address, out var ip));
        Assert.Equal(expected, VpnPlan.IsPublic(ip));
    }

    [Fact]
    public void The_check_says_ready_only_when_the_firewall_holds_the_address_the_internet_sees()
    {
        Assert.Equal(Reachability.Ready, VpnPlan.Check("41.193.12.57", "41.193.12.57", Now).Outcome);
        Assert.Equal(Reachability.NotPublic, VpnPlan.Check("192.168.1.10", "41.193.12.57", Now).Outcome);
        Assert.Equal(Reachability.NotPublic, VpnPlan.Check("100.70.1.2", "41.193.12.57", Now).Outcome);
        Assert.Contains("carrier-grade NAT", VpnPlan.Check("100.70.1.2", "41.193.12.57", Now).Advice);
        Assert.Contains("bridge mode", VpnPlan.Check("192.168.1.10", "41.193.12.57", Now).Advice);
        Assert.Equal(Reachability.Different, VpnPlan.Check("41.193.12.57", "41.193.12.99", Now).Outcome);
        Assert.Equal(Reachability.NoAnswer, VpnPlan.Check("41.193.12.57", null, Now).Outcome);
        Assert.Equal(Reachability.NoAddress, VpnPlan.Check("", null, Now).Outcome);
        Assert.Equal("41.193.12.57", VpnPlan.ParseTrace("fl=12f\nh=1.1.1.1\nip=41.193.12.57\nts=1795\nvisit_scheme=https\n"));
        Assert.Equal("", VpnPlan.ParseTrace("ip=2001:db8::1\n"));
    }

    [Fact]
    public void Switched_off_it_changes_nothing_at_all_in_the_generated_files()
    {
        var off = new FirewallConfig { SetupComplete = true, WanInterface = "enp1s0", LanInterface = "enp2s0" };
        var on = On();
        on.Vpn.Enabled = false;
        on.Vpn.Devices = [Phone()];
        Assert.Equal(ConfigRenderer.Nftables(off), ConfigRenderer.Nftables(on));
        Assert.Equal(ConfigRenderer.Dnsmasq(off), ConfigRenderer.Dnsmasq(on));
        Assert.Equal("", ConfigRenderer.Render(on).VpnPeers);
    }

    [Fact]
    public void Switched_on_the_tunnel_gets_the_home_treatment_and_internet_only_devices_are_turned_back_first()
    {
        var c = On(Phone(), Phone(Key2, "10.66.0.3", VpnAccess.InternetOnly));
        c.Filter.Level = FilterLevel.Security;
        c.Rules.Add(new FirewallRule { Name = "No telnet", Protocol = Protocol.Tcp, Ports = "23" });
        var nft = ConfigRenderer.Nftables(c);
        Assert.Contains("elements = { 10.66.0.3 }", nft);
        Assert.Contains("iifname { \"enp1s0\", \"enp2s0\" } udp dport 51820 accept comment \"VPN\"", nft);
        Assert.Contains("iifname \"palisade-wg\" ip saddr != @vpn_internet_only tcp dport", nft);
        Assert.Contains("iifname \"palisade-wg\" meta l4proto { tcp, udp } th dport 53 counter redirect to :53", nft);
        Assert.Contains("iifname \"palisade-wg\" oifname \"enp1s0\" meta l4proto { tcp, udp } th dport 853 counter reject", nft);
        Assert.Contains("iifname { \"enp2s0\", \"palisade-wg\" } oifname \"enp1s0\" tcp dport { 23 }", nft);

        // In the forward chain the internet-only line comes before every accept that could let such a device home.
        var forward = nft[nft.IndexOf("chain forward", StringComparison.Ordinal)..];
        var turnBack = forward.IndexOf("@vpn_internet_only oifname != \"enp1s0\" counter reject", StringComparison.Ordinal);
        Assert.True(turnBack > 0);
        Assert.True(turnBack < forward.IndexOf("ct state established,related accept", StringComparison.Ordinal));
        Assert.True(turnBack < forward.IndexOf("VPN devices to home", StringComparison.Ordinal));

        var dns = ConfigRenderer.Dnsmasq(c);
        Assert.Contains("interface=palisade-wg\nno-dhcp-interface=palisade-wg\n", dns);
    }

    [Fact]
    public void Each_device_is_allowed_exactly_its_own_address_and_the_files_hold_no_private_key()
    {
        var peers = VpnPlan.PeersText(On(Phone()).Vpn);
        Assert.Equal("[Interface]\nListenPort = 51820\n\n[Peer]\n# Annas phone\nPublicKey = " + Key1 + "\nAllowedIPs = 10.66.0.2/32\n", peers);
        Assert.DoesNotContain("PrivateKey", peers);
        Assert.DoesNotContain("PrivateKey", JsonSerializer.Serialize(On(Phone()), PalisadeJson.Options));
    }

    [Fact]
    public void The_client_settings_send_everything_home_and_use_the_home_name_server()
    {
        var c = On(Phone());
        c.Vpn.DuckDnsName = "smithhome";
        var text = VpnPlan.ClientConfig(c.Vpn, c.Vpn.Devices[0], "PRIVATE=", Key2, VpnPlan.EndpointHost(c.Vpn, "41.193.12.57"));
        Assert.Contains("PrivateKey = PRIVATE=\n", text);
        Assert.Contains("Address = 10.66.0.2/32\n", text);
        Assert.Contains("DNS = 10.66.0.1, home.arpa\n", text);
        Assert.Contains($"PublicKey = {Key2}\n", text);
        Assert.Contains("Endpoint = smithhome.duckdns.org:51820\n", text);
        Assert.Contains("AllowedIPs = 0.0.0.0/0, ::/0\n", text);
        Assert.Equal("annas-phone.conf", VpnPlan.FileName(c.Vpn.Devices[0]));
        Assert.Equal("a-much-longer-n.conf", VpnPlan.FileName(new VpnDevice { Name = "A much longer name" }));
        Assert.Equal("41.193.12.57", VpnPlan.EndpointHost(new VpnSettings(), "41.193.12.57"));
    }

    [Theory]
    [InlineData("192.168.50.1", 24, "overlaps your network")]
    [InlineData("8.8.8.1", 24, "private address")]
    [InlineData("10.66.0.0", 24, "first or last")]
    [InlineData("10.66.0.1", 20, "between /24 and /28")]
    public void A_vpn_network_that_cannot_work_is_refused(string address, int prefix, string expected)
    {
        var c = On();
        (c.Vpn.Address, c.Vpn.Prefix) = (address, prefix);
        Assert.Contains(ConfigValidator.Validate(c), i => i.Message.Contains(expected));
    }

    [Fact]
    public void Other_checks_hold_the_port_name_and_keys_and_none_apply_while_off()
    {
        var c = On(Phone(), Phone(Key1, "10.66.0.3"));
        c.Vpn.DuckDnsName = "Not A Name";
        c.PortForwards.Add(new PortForward { Name = "game", Protocol = Protocol.Udp, ExternalPort = "51820", InternalAddress = "192.168.50.10" });
        var issues = ConfigValidator.Validate(c).Select(i => i.Message).ToList();
        Assert.Contains(issues, m => m.Contains("same key"));
        Assert.Contains(issues, m => m.Contains("DuckDNS name"));
        Assert.Contains(issues, m => m.Contains("already forwarded"));
        c.Vpn.Enabled = false;
        Assert.DoesNotContain(ConfigValidator.Validate(c), i => i.Field == "Vpn");
    }

    [Fact]
    public void New_devices_get_the_next_free_address_and_the_dump_tells_home_from_away()
    {
        var v = On(Phone(), Phone(Key2, "10.66.0.4")).Vpn;
        Assert.Equal("10.66.0.3", VpnPlan.NextAddress(v));
        var dump = $"SERVERPRIV\tSERVERPUB\t51820\toff\n{Key1}\t(none)\t41.13.7.9:51333\t10.66.0.2/32\t1795140000\t1200\t3400\t25\n{Key2}\t(none)\t192.168.50.120:40000\t10.66.0.4/32\t1795140100\t10\t20\t25\n";
        var peers = VpnPlan.ParseDump(dump, v, from => from.StartsWith("192.168.50.", StringComparison.Ordinal));
        Assert.Equal(2, peers.Count);
        Assert.False(peers[0].FromHome);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1795140000), peers[0].LastHandshake);
        Assert.True(peers[1].FromHome);
        Assert.Equal("flush set inet palisade vpn_internet_only\n", VpnPlan.InternetOnlyScript(v));
    }

    private sealed class Platform : ISystemPlatform
    {
        public Reachability Line { get; set; } = Reachability.Ready;
        public List<string> Log { get; } = [];
        private int _keys;
        public Task<IReadOnlyList<string>> CheckAsync(FirewallConfig config, GeneratedFiles files, CancellationToken ct) => Task.FromResult<IReadOnlyList<string>>([]);
        public Task ApplyAsync(FirewallConfig config, GeneratedFiles files, CancellationToken ct) { Log.Add($"apply:{config.Vpn.Enabled}:{config.Vpn.Devices.Count}"); return Task.CompletedTask; }
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
        public Task<SystemStatus> GetStatusAsync(FirewallConfig active, CancellationToken ct) => Task.FromResult(new SystemStatus());
        public Task<IReadOnlyList<DhcpLease>> GetLeasesAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<DhcpLease>>([]);
        public Task<UsageReport> GetUsageAsync(CancellationToken ct) => Task.FromResult(new UsageReport());
        public Task SetAccessAsync(IReadOnlyList<DeviceAccess> access, CancellationToken ct) => Task.CompletedTask;
        public Task<WifiStatus> GetWifiAsync(CancellationToken ct) => Task.FromResult(new WifiStatus());
        public Task<ApplyResult> SetWifiAsync(WifiRequest request, CancellationToken ct) => Task.FromResult(new ApplyResult { Ok = true });
        public Task SetApprovalsAsync(FirewallConfig live, CancellationToken ct) => Task.CompletedTask;
        public Task<IReadOnlyList<string>> GetNeighboursAsync(FirewallConfig live, CancellationToken ct) => Task.FromResult<IReadOnlyList<string>>([]);
        public Task<ReachabilityReport> CheckReachabilityAsync(FirewallConfig live, CancellationToken ct) => Task.FromResult(Line switch
        {
            Reachability.Ready => VpnPlan.Check("41.193.12.57", "41.193.12.57", Now),
            Reachability.NotPublic => VpnPlan.Check("100.70.1.2", "41.193.12.57", Now),
            _ => VpnPlan.Check("41.193.12.57", null, Now),
        });
        public Task<(string Private, string Public)> NewVpnKeysAsync(CancellationToken ct) => Task.FromResult(("PRIV" + ++_keys + "=", ++_keys % 2 == 0 ? Key1 : Key2));
        public Task<string> GetVpnServerKeyAsync(CancellationToken ct) => Task.FromResult(Key2);
        public Task SetVpnPeersAsync(FirewallConfig live, CancellationToken ct) { Log.Add($"peers:{live.Vpn.Devices.Count}"); return Task.CompletedTask; }
        public Task<VpnStatus> GetVpnStatusAsync(FirewallConfig live, CancellationToken ct) => Task.FromResult(new VpnStatus { Reachability = VpnPlan.Check("41.193.12.57", "41.193.12.57", Now) });
    }

    private static async Task<(FirewallEngine Engine, Platform Platform, string Folder)> SetUpAsync()
    {
        var platform = new Platform();
        var folder = Directory.CreateTempSubdirectory("palisade-vpn").FullName;
        var engine = new FirewallEngine(platform, folder, TimeSpan.FromSeconds(30));
        await engine.InitializeAsync();
        Assert.True((await engine.ApplyAsync(new FirewallConfig { WanInterface = "enp1s0", LanInterface = "enp2s0" })).Ok);
        await engine.ConfirmAsync();
        return (engine, platform, folder);
    }

    [Fact]
    public async Task Switching_on_is_refused_unless_the_line_is_reachable_and_then_waits_for_confirmation()
    {
        var (engine, platform, _) = await SetUpAsync();
        using var _ = engine;
        platform.Line = Reachability.NotPublic;
        var refused = await engine.SetVpnAsync(new VpnRequest { Enabled = true });
        Assert.False(refused.Ok);
        Assert.Contains("carrier-grade NAT", refused.Issues[0].Message);
        Assert.False((await engine.GetConfigAsync()).Vpn.Enabled);

        platform.Line = Reachability.Ready;
        var on = await engine.SetVpnAsync(new VpnRequest { Enabled = true, DuckDnsName = "SmithHome.duckdns.org" });
        Assert.True(on.Ok);
        Assert.True(on.ConfirmWithinSeconds > 0);
        Assert.Equal("smithhome", (await engine.GetConfigAsync()).Vpn.DuckDnsName);
        Assert.False((await engine.SetVpnAsync(new VpnRequest { Enabled = true, DuckDnsToken = "not-a-token" })).Ok);
    }

    [Fact]
    public async Task Devices_come_in_at_once_and_a_removed_one_never_comes_back_with_an_undo()
    {
        var (engine, platform, folder) = await SetUpAsync();
        using var _ = engine;
        Assert.True((await engine.SetVpnAsync(new VpnRequest { Enabled = true })).Ok);
        await engine.ConfirmAsync();

        var added = await engine.AddVpnDeviceAsync(new VpnDeviceRequest { Name = "Annas phone" });
        Assert.True(added.Ok, string.Join("; ", added.Issues.Select(i => i.Message)));
        Assert.Equal("10.66.0.2", added.Device!.Address);
        Assert.Contains("PrivateKey = PRIV", added.ClientConfig);
        Assert.Contains("Endpoint = 41.193.12.57:51820", added.ClientConfig);
        Assert.Null((await engine.GetStatusAsync()).PendingSecondsLeft);
        // The private key went to the page once and is kept nowhere.
        Assert.DoesNotContain("PRIV", await File.ReadAllTextAsync(Path.Combine(folder, "config.json")));
        Assert.False((await engine.AddVpnDeviceAsync(new VpnDeviceRequest { Name = "annas PHONE" })).Ok);

        // A change is pending when the phone is lost and removed; the change is then undone. The phone stays out.
        Assert.True((await engine.SetVpnAsync(new VpnRequest { Enabled = true, Port = 51821 })).Ok);
        Assert.True((await engine.RemoveVpnDeviceAsync(added.Device.Id)).Ok);
        await engine.RevertAsync();
        var config = await engine.GetConfigAsync();
        Assert.Equal(51820, config.Vpn.Port);
        Assert.Empty(config.Vpn.Devices);
        Assert.Equal("peers:0", platform.Log[^2]);
    }

    [Fact]
    public async Task Without_a_name_a_device_is_only_added_while_the_line_is_reachable_and_never_with_an_empty_address()
    {
        var (engine, platform, _) = await SetUpAsync();
        using var __ = engine;
        Assert.True((await engine.SetVpnAsync(new VpnRequest { Enabled = true })).Ok);
        await engine.ConfirmAsync();
        platform.Line = Reachability.NotPublic;
        var refused = await engine.AddVpnDeviceAsync(new VpnDeviceRequest { Name = "Annas phone" });
        Assert.False(refused.Ok);
        Assert.Contains("carrier-grade NAT", refused.Issues[0].Message);
        Assert.Empty((await engine.GetConfigAsync()).Vpn.Devices);
        platform.Line = Reachability.Ready;
        var added = await engine.AddVpnDeviceAsync(new VpnDeviceRequest { Name = "Annas phone" });
        Assert.Contains("Endpoint = 41.193.12.57:51820\n", added.ClientConfig);
        Assert.DoesNotContain("\r", added.ClientConfig);
    }

    [Fact]
    public async Task A_save_from_a_screen_without_the_vpn_can_not_switch_it_off_or_forget_devices()
    {
        var (engine, _, _) = await SetUpAsync();
        using var __ = engine;
        Assert.True((await engine.SetVpnAsync(new VpnRequest { Enabled = true })).Ok);
        await engine.ConfirmAsync();
        Assert.True((await engine.AddVpnDeviceAsync(new VpnDeviceRequest { Name = "Laptop" })).Ok);

        // Like the v1.7 app: a whole config with no VPN section.
        Assert.True((await engine.ApplyAsync(new FirewallConfig { WanInterface = "enp1s0", LanInterface = "enp2s0", LanAddress = "192.168.50.1" })).Ok);
        await engine.ConfirmAsync();
        var config = await engine.GetConfigAsync();
        Assert.True(config.Vpn.Enabled);
        Assert.Single(config.Vpn.Devices);
    }
}
