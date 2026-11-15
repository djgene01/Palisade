using Palisade.Core;

namespace Palisade.Core.Tests;

public class CoreTests
{
    private static FirewallConfig Sample() => new()
    {
        SetupComplete = true,
        WanInterface = "enp1s0",
        LanInterface = "enp2s0",
        Dhcp = { Reservations = { new Reservation { Name = "nas", Mac = "aa:bb:cc:dd:ee:01", Address = "192.168.50.10" } } },
        PortForwards =
        {
            new PortForward { Name = "Web server", Protocol = Protocol.Tcp, ExternalPort = "443", InternalAddress = "192.168.50.10", InternalPort = 8443 },
            new PortForward { Name = "Game", Protocol = Protocol.TcpUdp, ExternalPort = "27000-27010", InternalAddress = "192.168.50.20" },
        },
        Rules =
        {
            new FirewallRule { Name = "Block tablet", Source = "192.168.50.30" },
            new FirewallRule { Name = "No telnet", Protocol = Protocol.Tcp, Ports = "23, 2323" },
            new FirewallRule { Name = "Disabled", Destination = "203.0.113.0/24", Enabled = false },
        },
    };

    [Fact]
    public void Sample_config_is_valid() => Assert.Empty(ConfigValidator.Validate(Sample()));

    [Fact]
    public void Nftables_has_baseline_and_user_rules()
    {
        var text = ConfigRenderer.Nftables(Sample());

        Assert.StartsWith("#!/usr/sbin/nft -f\n", text);
        Assert.DoesNotContain('\r', text);
        Assert.Contains("flush ruleset", text);
        Assert.Contains("type filter hook input priority filter; policy drop;", text);
        Assert.Contains("iifname \"enp2s0\" udp dport { 53, 67 } accept", text);
        Assert.Contains("iifname \"enp2s0\" tcp dport { 22, 8080, 8081 } accept", text);
        Assert.DoesNotContain("manage from internet side", text);
        Assert.Contains("iifname \"enp2s0\" oifname \"enp1s0\" ip saddr 192.168.50.30 counter reject with icmpx type admin-prohibited comment \"Block tablet\"", text);
        Assert.Contains("iifname \"enp2s0\" oifname \"enp1s0\" tcp dport { 23, 2323 } counter reject", text);
        Assert.DoesNotContain("203.0.113.0", text);
        Assert.Contains("iifname \"enp1s0\" tcp dport 443 dnat to 192.168.50.10:8443 comment \"Web server\"", text);
        Assert.Contains("iifname \"enp1s0\" tcp dport 27000-27010 dnat to 192.168.50.20 comment \"Game\"", text);
        Assert.Contains("iifname \"enp1s0\" udp dport 27000-27010 dnat to 192.168.50.20 comment \"Game\"", text);
        Assert.Contains("oifname \"enp1s0\" masquerade", text);

        // User rules must be evaluated before the blanket accepts.
        Assert.True(text.IndexOf("Block tablet", StringComparison.Ordinal) < text.IndexOf("home network to internet", StringComparison.Ordinal));
    }

    [Fact]
    public void Management_from_wan_and_nat_follow_their_switches()
    {
        var c = Sample();
        c.AllowManagementFromWan = true;
        c.NatEnabled = false;
        c.PortForwards.Clear();
        var text = ConfigRenderer.Nftables(c);

        Assert.Contains("iifname \"enp1s0\" tcp dport { 22, 8080, 8081 } accept comment \"manage from internet side\"", text);
        Assert.DoesNotContain("masquerade", text);
    }

    [Fact]
    public void Dnsmasq_serves_dhcp_and_dns_on_lan_only()
    {
        var text = ConfigRenderer.Dnsmasq(Sample());

        Assert.Contains("interface=enp2s0\n", text);
        Assert.Contains("dhcp-range=192.168.50.100,192.168.50.200,255.255.255.0,12h\n", text);
        Assert.Contains("dhcp-option=option:router,192.168.50.1\n", text);
        Assert.Contains("dhcp-option=option:dns-server,192.168.50.1\n", text);
        Assert.Contains("dhcp-host=aa:bb:cc:dd:ee:01,192.168.50.10,nas\n", text);
        Assert.Contains("server=1.1.1.1\n", text);
        Assert.DoesNotContain('\r', text);

        var off = Sample();
        off.Dhcp.Enabled = false;
        Assert.DoesNotContain("dhcp-range", ConfigRenderer.Dnsmasq(off));
    }

    [Theory]
    [InlineData("x\" accept; drop")]
    [InlineData("name\nflush ruleset")]
    [InlineData("back\\slash")]
    [InlineData("")]
    public void Unsafe_names_are_rejected_and_never_rendered(string name)
    {
        var c = Sample();
        c.Rules[0].Name = name;

        Assert.NotEmpty(ConfigValidator.Validate(c));
        Assert.Throws<InvalidOperationException>(() => ConfigRenderer.Nftables(c));
    }

    [Theory]
    [InlineData("192.168.50.1; drop")]
    [InlineData("192.168.050.0001")]
    [InlineData("1.2.3")]
    [InlineData("10.0.0.0/33")]
    public void Unsafe_addresses_are_rejected(string address)
    {
        var c = Sample();
        c.Rules[0].Source = address;

        Assert.NotEmpty(ConfigValidator.Validate(c));
        Assert.Throws<InvalidOperationException>(() => ConfigRenderer.Nftables(c));
    }

    [Fact]
    public void Validator_catches_common_mistakes()
    {
        var c = Sample();
        c.LanInterface = c.WanInterface;
        c.Dhcp.RangeStart = "192.168.50.1";
        c.Dhcp.RangeEnd = "192.168.60.5";
        c.PortForwards[0].InternalAddress = "10.9.9.9";
        c.PortForwards.Add(new PortForward { Name = "Clash", ExternalPort = "443", InternalAddress = "192.168.50.11" });
        c.Rules[1].Ports = "http";
        var fields = ConfigValidator.Validate(c).Select(i => i.Field).ToList();

        Assert.Contains("LanInterface", fields);
        Assert.Contains("Dhcp.RangeStart", fields);
        Assert.Contains("Dhcp.RangeEnd", fields);
        Assert.Contains($"PortForward.{c.PortForwards[0].Id}", fields);
        Assert.Contains($"PortForward.{c.PortForwards[2].Id}", fields);
        Assert.Contains($"Rule.{c.Rules[1].Id}", fields);
    }

    [Fact]
    public void Address_and_port_parsing()
    {
        Assert.True(AddressSpec.TryNormalize("10.1.2.3/8", out var cidr));
        Assert.Equal("10.0.0.0/8", cidr);
        Assert.True(PortSpec.TryParseList("80, 443,8000-8010", out var ports));
        Assert.Equal("80, 443, 8000-8010", string.Join(", ", ports));
        Assert.False(PortSpec.TryParseRange("0", out _));
        Assert.False(PortSpec.TryParseRange("90-80", out _));
        Assert.False(PortSpec.TryParseRange("70000", out _));
        Assert.True(ConfigValidator.TryNormalizeMac("AA-BB-CC-DD-EE-FF", out var mac));
        Assert.Equal("aa:bb:cc:dd:ee:ff", mac);
    }

    [Fact]
    public void Config_saved_before_the_filter_existed_renders_as_before()
    {
        var old = System.Text.Json.JsonSerializer.Serialize(Sample(), PalisadeJson.Options);
        var start = old.IndexOf("\"filter\"", StringComparison.Ordinal);
        Assert.True(start > 0);
        old = old[..old.LastIndexOf(',', start)] + "\n}";
        var c = System.Text.Json.JsonSerializer.Deserialize<FirewallConfig>(old, PalisadeJson.Options)!;

        Assert.Equal(FilterLevel.Off, c.Filter.Level);
        Assert.Empty(ConfigValidator.Validate(c));
        var files = ConfigRenderer.Render(c);
        Assert.Empty(files.DnsInstances);
        Assert.DoesNotContain("redirect", files.Nftables);
        Assert.DoesNotContain("853", files.Nftables);
        Assert.DoesNotContain("ether saddr", files.Nftables);
        Assert.Contains("server=1.1.1.1\n", files.Dnsmasq);
        Assert.DoesNotContain("use-application-dns.net", files.Dnsmasq);
    }

    private static FirewallConfig Filtered()
    {
        var c = Sample();
        c.Filter = new ContentFilter
        {
            Level = FilterLevel.Family,
            BlockedSites = { "tiktok.com" },
            AllowedSites = { "reddit.com" },
            Devices =
            {
                new DeviceFilter { Mac = "aa:bb:cc:dd:ee:10", Name = "Mum laptop", Level = FilterLevel.Security },
                new DeviceFilter { Mac = "aa:bb:cc:dd:ee:11", Name = "Dad phone", Level = FilterLevel.Off },
                new DeviceFilter { Mac = "aa:bb:cc:dd:ee:12", Name = "Same as network", Level = FilterLevel.Family },
            },
        };
        return c;
    }

    [Fact]
    public void Filter_picks_one_kind_of_name_server_per_level()
    {
        var c = Filtered();
        Assert.Empty(ConfigValidator.Validate(c));
        var files = ConfigRenderer.Render(c);

        // The network's own server asks only the family service, never the plain one as well.
        Assert.Contains("server=185.228.168.168\n", files.Dnsmasq);
        Assert.DoesNotContain("server=1.1.1.1\n", files.Dnsmasq);
        Assert.Contains("local=/tiktok.com/\n", files.Dnsmasq);
        Assert.Contains("local=/use-application-dns.net/\n", files.Dnsmasq);
        Assert.Contains("server=/reddit.com/1.1.1.1\n", files.Dnsmasq);
        Assert.Contains("dhcp-range=", files.Dnsmasq);

        Assert.Equal(["off", "security"], files.DnsInstances.Select(i => i.Name));
        var off = files.DnsInstances[0];
        Assert.Contains("port=5380\n", off.Conf);
        Assert.Contains("server=1.1.1.1\n", off.Conf);
        Assert.Contains("local=/tiktok.com/\n", off.Conf);
        Assert.DoesNotContain("use-application-dns.net", off.Conf);
        Assert.DoesNotContain("dhcp-range", off.Conf);
        var security = files.DnsInstances[1];
        Assert.Contains("port=5381\n", security.Conf);
        Assert.Contains("server=1.1.1.2\n", security.Conf);
        Assert.DoesNotContain("185.228", security.Conf);
        Assert.All(files.DnsInstances, i => Assert.DoesNotContain('\r', i.Conf));
    }

    [Fact]
    public void Filter_forces_lookups_through_the_firewall()
    {
        var text = ConfigRenderer.Nftables(Filtered());

        Assert.Contains("iifname \"enp2s0\" meta l4proto { tcp, udp } th dport { 5380, 5381 } accept", text);
        Assert.Contains("iifname \"enp2s0\" ether saddr { aa:bb:cc:dd:ee:11 } meta l4proto { tcp, udp } th dport 53 counter redirect to :5380", text);
        Assert.Contains("iifname \"enp2s0\" ether saddr { aa:bb:cc:dd:ee:10 } meta l4proto { tcp, udp } th dport 53 counter redirect to :5381", text);
        Assert.Contains("iifname \"enp2s0\" meta l4proto { tcp, udp } th dport 53 counter redirect to :53 ", text);
        Assert.Contains("iifname \"enp2s0\" oifname \"enp1s0\" ether saddr != { aa:bb:cc:dd:ee:11 } meta l4proto { tcp, udp } th dport 853 counter reject", text);
        // A device whose own level equals the network's needs no rule of its own.
        Assert.DoesNotContain("aa:bb:cc:dd:ee:12", text);
        // Per-device redirects must be tried before the catch-all, and the 853 block before any user "allow" rule.
        Assert.True(text.IndexOf("redirect to :5381", StringComparison.Ordinal) < text.IndexOf("redirect to :53 ", StringComparison.Ordinal));
        Assert.True(text.IndexOf("dport 853", StringComparison.Ordinal) < text.IndexOf("Block tablet", StringComparison.Ordinal));
    }

    [Fact]
    public void Blocked_sites_alone_also_switch_enforcement_on()
    {
        var c = Sample();
        c.Filter.BlockedSites.Add("tiktok.com");
        var files = ConfigRenderer.Render(c);

        Assert.Contains("redirect to :53 ", files.Nftables);
        Assert.Contains("local=/tiktok.com/\n", files.Dnsmasq);
        Assert.Contains("server=1.1.1.1\n", files.Dnsmasq);
        Assert.Empty(files.DnsInstances);
    }

    [Theory]
    [InlineData("tiktok.com/\naddress=/#/1.2.3.4")]
    [InlineData("tiktok.com/#")]
    [InlineData("TikTok.com")]
    [InlineData("tiktok")]
    [InlineData("-bad.com")]
    [InlineData("a b.com")]
    [InlineData("")]
    public void Unsafe_site_names_are_rejected_and_never_rendered(string site)
    {
        foreach (var allowed in new[] { false, true })
        {
            var c = Filtered();
            (allowed ? c.Filter.AllowedSites : c.Filter.BlockedSites).Add(site);

            Assert.NotEmpty(ConfigValidator.Validate(c));
            Assert.Throws<InvalidOperationException>(() => ConfigRenderer.Render(c));
        }
    }

    [Theory]
    [InlineData("aa:bb:cc:dd:ee:1")]
    [InlineData("AA:BB:CC:DD:EE:10")]
    [InlineData("aa:bb:cc:dd:ee:10 } accept; ip saddr { 1.1.1.1")]
    public void Unsafe_hardware_addresses_are_rejected_and_never_rendered(string mac)
    {
        var c = Filtered();
        c.Filter.Devices[0].Mac = mac;

        Assert.NotEmpty(ConfigValidator.Validate(c));
        Assert.Throws<InvalidOperationException>(() => ConfigRenderer.Nftables(c));
    }

    [Fact]
    public void Filter_validation_catches_common_mistakes()
    {
        var c = Filtered();
        c.Filter.AllowedSites.Add("tiktok.com");
        c.Filter.BlockedSites.Add("tiktok.com");
        c.Filter.Devices.Add(new DeviceFilter { Mac = "aa:bb:cc:dd:ee:10", Name = "Twice", Level = FilterLevel.Adult });
        var fields = ConfigValidator.Validate(c).Select(i => i.Field).ToList();

        Assert.Contains("Filter.BlockedSites", fields);
        Assert.Contains("Filter.AllowedSites", fields);
        Assert.Contains("Filter.Device.aa:bb:cc:dd:ee:10", fields);
    }

    [Theory]
    [InlineData("https://www.TikTok.com/@someone?lang=en", "tiktok.com")]
    [InlineData("  reddit.com.  ", "reddit.com")]
    [InlineData("*.example.co.za", "example.co.za")]
    [InlineData("www.com", "www.com")]
    [InlineData("m.youtube.com:443/watch", "m.youtube.com")]
    public void Pasted_addresses_are_reduced_to_a_site_name(string pasted, string expected)
    {
        Assert.True(SiteName.TryNormalize(pasted, out var name));
        Assert.Equal(expected, name);
        Assert.False(SiteName.TryNormalize("not a site", out _));
        Assert.False(SiteName.TryNormalize("192.168.1.1", out _));
    }

    [Fact]
    public void Lease_file_is_parsed()
    {
        var leases = LeaseParser.Parse("1800000000 aa:bb:cc:dd:ee:01 192.168.50.101 laptop 01:aa:bb:cc:dd:ee:01\n1800000100 AA:BB:CC:DD:EE:02 192.168.50.102 * *\ngarbage\n");

        Assert.Equal(2, leases.Count);
        Assert.Equal("laptop", leases[0].Hostname);
        Assert.Null(leases[1].Hostname);
        Assert.Equal("aa:bb:cc:dd:ee:02", leases[1].Mac);
    }
}

public class EngineTests
{
    private sealed class FakePlatform : ISystemPlatform
    {
        public List<string> Log { get; } = [];
        public bool FailNextApply { get; set; }
        public List<string> CheckProblems { get; } = [];

        public Task<IReadOnlyList<string>> CheckAsync(FirewallConfig config, GeneratedFiles files, CancellationToken ct) => Task.FromResult<IReadOnlyList<string>>(CheckProblems);

        public Task ApplyAsync(FirewallConfig config, GeneratedFiles files, CancellationToken ct)
        {
            if (FailNextApply)
            {
                FailNextApply = false;
                throw new InvalidOperationException("boom");
            }
            Log.Add($"apply:{config.LanAddress}");
            return Task.CompletedTask;
        }

        public Task ClearAsync(CancellationToken ct)
        {
            Log.Add("clear");
            return Task.CompletedTask;
        }

        public Task<SystemStatus> GetStatusAsync(FirewallConfig active, CancellationToken ct) => Task.FromResult(new SystemStatus());
        public Task<IReadOnlyList<DhcpLease>> GetLeasesAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<DhcpLease>>([]);
    }

    private static FirewallConfig Config(string lan = "192.168.50.1") => new() { WanInterface = "wan0", LanInterface = "lan0", LanAddress = lan };

    private static string TempDir() => Directory.CreateTempSubdirectory("palisade-test").FullName;

    [Fact]
    public async Task Confirmed_change_is_saved_and_survives_restart()
    {
        var dir = TempDir();
        var platform = new FakePlatform();
        using (var engine = new FirewallEngine(platform, dir, TimeSpan.FromSeconds(30)))
        {
            await engine.InitializeAsync();
            Assert.True((await engine.ApplyAsync(Config())).Ok);
            Assert.NotNull((await engine.GetStatusAsync()).PendingSecondsLeft);
            await engine.ConfirmAsync();
            Assert.Null((await engine.GetStatusAsync()).PendingSecondsLeft);
        }

        using var restarted = new FirewallEngine(platform, dir, TimeSpan.FromSeconds(30));
        await restarted.InitializeAsync();
        Assert.True((await restarted.GetConfigAsync()).SetupComplete);
        Assert.Equal(["apply:192.168.50.1", "apply:192.168.50.1"], platform.Log);
    }

    [Fact]
    public async Task Unconfirmed_first_setup_is_cleared_when_time_runs_out()
    {
        var platform = new FakePlatform();
        using var engine = new FirewallEngine(platform, TempDir(), TimeSpan.FromMilliseconds(150));
        await engine.InitializeAsync();
        Assert.True((await engine.ApplyAsync(Config())).Ok);

        await Task.Delay(800);

        Assert.Equal(["apply:192.168.50.1", "clear"], platform.Log);
        Assert.False((await engine.GetConfigAsync()).SetupComplete);
    }

    [Fact]
    public async Task Unconfirmed_change_goes_back_to_last_confirmed_config()
    {
        var platform = new FakePlatform();
        using var engine = new FirewallEngine(platform, TempDir(), TimeSpan.FromSeconds(30));
        await engine.InitializeAsync();
        await engine.ApplyAsync(Config());
        await engine.ConfirmAsync();

        var changed = Config("192.168.60.1");
        changed.Dhcp.RangeStart = "192.168.60.100";
        changed.Dhcp.RangeEnd = "192.168.60.200";
        Assert.True((await engine.ApplyAsync(changed)).Ok);
        await engine.RevertAsync();

        Assert.Equal(["apply:192.168.50.1", "apply:192.168.60.1", "apply:192.168.50.1"], platform.Log);
        Assert.Equal("192.168.50.1", (await engine.GetConfigAsync()).LanAddress);
    }

    [Fact]
    public async Task Invalid_or_failing_changes_never_become_pending()
    {
        var platform = new FakePlatform();
        using var engine = new FirewallEngine(platform, TempDir(), TimeSpan.FromSeconds(30));
        await engine.InitializeAsync();

        var invalid = Config();
        invalid.LanInterface = "wan0";
        Assert.False((await engine.ApplyAsync(invalid)).Ok);

        platform.CheckProblems.Add("syntax error");
        Assert.False((await engine.ApplyAsync(Config())).Ok);
        platform.CheckProblems.Clear();

        platform.FailNextApply = true;
        Assert.False((await engine.ApplyAsync(Config())).Ok);

        Assert.Null((await engine.GetStatusAsync()).PendingSecondsLeft);
        Assert.Equal(["clear"], platform.Log);
    }
}
