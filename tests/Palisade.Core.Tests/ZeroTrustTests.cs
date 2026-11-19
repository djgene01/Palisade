using Palisade.Core;

namespace Palisade.Core.Tests;

public class ZeroTrustTests
{
    private const string Laptop = "aa:bb:cc:00:00:01";
    private const string Nas = "aa:bb:cc:dd:ee:01";
    private const string Stranger = "02:00:00:00:00:aa";

    private static FirewallConfig Sample() => new()
    {
        SetupComplete = true,
        WanInterface = "enp1s0",
        LanInterface = "enp2s0",
        Dhcp = { Reservations = { new Reservation { Name = "nas", Mac = Nas, Address = "192.168.50.10" } } },
        PortForwards = { new PortForward { Name = "Web server", Protocol = Protocol.Tcp, ExternalPort = "443", InternalAddress = "192.168.50.10" } },
        Rules = { new FirewallRule { Name = "No telnet", Protocol = Protocol.Tcp, Ports = "23" } },
    };

    private static FirewallConfig On(params string[] approved)
    {
        var c = Sample();
        c.ZeroTrust.Enabled = true;
        c.ZeroTrust.Approved = [.. approved.Select(m => new ApprovedDevice { Mac = m, Name = "", ApprovedAt = DateTimeOffset.UnixEpoch })];
        return c;
    }

    [Fact]
    public void Switched_off_it_changes_nothing_at_all_in_the_generated_files()
    {
        var plain = ConfigRenderer.Render(Sample());
        var off = Sample();
        off.ZeroTrust = new ZeroTrustSettings
        {
            Enabled = false, HoldingAddress = "10.77.0.1",
            Approved = [new ApprovedDevice { Mac = Laptop, Name = "Laptop" }], Blocked = [new BlockedDevice { Mac = Stranger }],
        };
        var rendered = ConfigRenderer.Render(off);

        Assert.Equal(plain.Nftables, rendered.Nftables);
        Assert.Equal(plain.Dnsmasq, rendered.Dnsmasq);
        Assert.Equal(plain.LanInterface, rendered.LanInterface);
        Assert.Equal(ConfigRenderer.LanAddresses(Sample()), ConfigRenderer.LanAddresses(off));
    }

    [Fact]
    public void Approved_devices_are_written_into_the_rules_that_load_at_boot()
    {
        var text = ConfigRenderer.Nftables(On(Laptop, Nas));
        Assert.Contains("    set approved {\n        type ether_addr;\n        elements = { aa:bb:cc:00:00:01, aa:bb:cc:dd:ee:01 }\n    }", text);
        Assert.Contains("set held_flows { type ether_addr . ipv4_addr . inet_proto . inet_service; size 4096; flags dynamic,timeout; timeout 7d; counter; }", text);
    }

    [Fact]
    public void With_nobody_approved_the_set_is_still_valid()
    {
        var text = ConfigRenderer.Nftables(On());
        Assert.Contains("    set approved {\n        type ether_addr;\n    }", text);
        Assert.DoesNotContain("elements", text);
    }

    [Fact]
    public void Waiting_devices_are_counted_captured_and_dropped_on_separate_lines_before_anything_is_accepted()
    {
        var text = ConfigRenderer.Nftables(On(Laptop));
        var input = Chain(text, "input");
        var forward = Chain(text, "forward");
        const string notApproved = "iifname \"enp2s0\" ether saddr != @approved";

        // In the firewall's own chain: an address request is the one thing let through, then count, capture, drop.
        var dhcp = Line(input, $"{notApproved} udp sport 68 udp dport 67 accept");
        var count = Line(input, $"{notApproved} meta l4proto {{ tcp, udp }} update @held_flows {{ ether saddr . ip daddr . meta l4proto . th dport }}");
        var capture = Line(input, $"{notApproved} limit rate 100/second log group 7");
        var drop = Line(input, $"{notApproved} counter drop comment \"waiting for approval\"");
        Assert.True(Line(input, "iif \"lo\" accept") < dhcp && dhcp < count && count < capture && capture < drop);
        // Before anything that accepts: established traffic, ping, name lookups and the management ports.
        Assert.True(drop < Line(input, "ct state established,related accept"));
        Assert.True(drop < Line(input, "meta l4proto { icmp, ipv6-icmp } accept"));
        Assert.True(drop < Line(input, "udp dport { 53, 67 } accept"));
        Assert.True(drop < Line(input, "tcp dport { 22, 8080, 8081, 8443 } accept"));
        // The drop has no IPv4 match of its own, so it covers IPv6 too.
        Assert.DoesNotContain("ip ", input[drop].Replace("ip daddr", ""));

        // In forwarding: the same three lines first, then nothing may reach into the holding zone.
        Assert.Equal(0, Line(forward, $"{notApproved} meta l4proto {{ tcp, udp }} update @held_flows"));
        Assert.True(Line(forward, $"{notApproved} counter drop") < Line(forward, "ip daddr 10.99.0.0/24 counter drop comment \"nothing reaches the holding zone\""));
        Assert.True(Line(forward, "ip daddr 10.99.0.0/24") < Line(forward, "ct state established,related accept"));
    }

    [Fact]
    public void Approved_devices_get_a_home_address_and_everything_else_a_short_one_in_the_holding_zone()
    {
        var dns = ConfigRenderer.Dnsmasq(On(Laptop));
        Assert.Contains("dhcp-hostsfile=/etc/palisade/zt-hosts\n", dns);
        Assert.Contains("dhcp-range=tag:known,192.168.50.100,192.168.50.200,255.255.255.0,12h\n", dns);
        Assert.Contains("dhcp-range=set:holding,tag:!known,10.99.0.100,10.99.0.250,255.255.255.0,2m\n", dns);
        Assert.Contains("dhcp-option=tag:!holding,option:router,192.168.50.1\n", dns);
        Assert.Contains("dhcp-option=tag:holding,option:router\n", dns);
        Assert.Contains("dhcp-option=tag:holding,option:dns-server\n", dns);
        // A reservation alone would count as "known", so an unapproved device does not keep one.
        Assert.DoesNotContain("dhcp-host=", dns);
        Assert.DoesNotContain("aa:bb:cc:dd:ee:01", ZeroTrustPlan.HostsFileText(On(Laptop)));
    }

    [Fact]
    public void An_approved_device_keeps_its_fixed_address_on_its_one_line_in_the_hosts_file()
    {
        // dnsmasq takes one entry per device. With a bare line in the hosts file and the fixed address in the main
        // config, real dnsmasq handed the device a free address from the range instead (seen on v1.4).
        var c = On(Nas, Laptop);
        Assert.DoesNotContain("dhcp-host=", ConfigRenderer.Dnsmasq(c));
        var hosts = ZeroTrustPlan.HostsFileText(c).Split('\n');
        Assert.Contains("aa:bb:cc:dd:ee:01,192.168.50.10,nas", hosts);
        Assert.Contains(Laptop, hosts);
        Assert.Single(hosts, l => l.StartsWith(Nas, StringComparison.Ordinal));
        // With the mode off, nothing changes: the fixed address stays in the main config.
        Assert.Contains("dhcp-host=aa:bb:cc:dd:ee:01,192.168.50.10,nas\n", ConfigRenderer.Dnsmasq(Sample()));
    }

    [Fact]
    public void A_small_holding_zone_hands_out_all_of_its_addresses_but_the_firewalls()
    {
        var c = On();
        (c.ZeroTrust.HoldingAddress, c.ZeroTrust.HoldingPrefix) = ("10.99.0.1", 27);
        var (first, last) = ZeroTrustPlan.HoldingPool(c.ZeroTrust);
        Assert.Equal(("10.99.0.2", "10.99.0.30"), (first.ToString(), last.ToString()));
        Assert.Contains("10.99.0.1/27", ConfigRenderer.LanAddresses(c));
    }

    [Fact]
    public void The_hosts_file_lists_approved_devices_and_ignores_blocked_ones()
    {
        var c = On(Laptop);
        c.ZeroTrust.Blocked = [new BlockedDevice { Mac = Stranger }];
        Assert.Equal("# Generated by Palisade. Do not edit: approvals change it.\naa:bb:cc:00:00:01\n02:00:00:00:00:aa,ignore\n", ZeroTrustPlan.HostsFileText(c));
        Assert.Equal("flush set inet palisade approved\nadd element inet palisade approved { aa:bb:cc:00:00:01 }\n", ZeroTrustPlan.SetScript(c.ZeroTrust));
        Assert.Equal("flush set inet palisade approved\n", ZeroTrustPlan.SetScript(On().ZeroTrust));
    }

    [Theory]
    [InlineData("192.168.50.1", 24, "overlaps your network")]
    [InlineData("10.99.0.1", 22, "between 16 and 256")]
    [InlineData("8.8.8.1", 24, "private address")]
    [InlineData("10.99.0.0", 24, "first or last")]
    [InlineData("not an address", 24, "private address")]
    public void A_holding_zone_that_cannot_work_is_refused(string address, int prefix, string expected)
    {
        var c = On();
        (c.ZeroTrust.HoldingAddress, c.ZeroTrust.HoldingPrefix) = (address, prefix);
        Assert.Contains(ConfigValidator.Validate(c), i => i.Message.Contains(expected));
    }

    [Fact]
    public void Switched_off_the_holding_zone_never_stands_in_the_way_of_a_home_network_on_its_range()
    {
        var c = Sample();
        (c.LanAddress, c.LanPrefix) = ("10.99.0.1", 24);
        c.Dhcp.RangeStart = "10.99.0.100";
        c.Dhcp.RangeEnd = "10.99.0.200";
        Assert.DoesNotContain(ConfigValidator.Validate(c), i => i.Field.StartsWith("ZeroTrust", StringComparison.Ordinal));
        c.ZeroTrust.Enabled = true;
        Assert.Contains(ConfigValidator.Validate(c), i => i.Message.Contains("overlaps your network"));
    }

    [Fact]
    public async Task Switching_off_with_nothing_but_enabled_false_keeps_the_holding_zone()
    {
        using var engine = await SetUpAsync(new Platform());
        await engine.SetZeroTrustAsync(new ZeroTrustRequest { Enabled = true, HoldingAddress = "172.30.9.1", HoldingPrefix = 26 });
        await engine.ConfirmAsync();

        // What the emergency command in the README sends: {"enabled":false}, which leaves the other fields at their defaults.
        Assert.True((await engine.SetZeroTrustAsync(new ZeroTrustRequest { Enabled = false })).Ok);
        await engine.ConfirmAsync();
        var z = (await engine.GetConfigAsync()).ZeroTrust;
        Assert.False(z.Enabled);
        Assert.Equal(("172.30.9.1", 26), (z.HoldingAddress, z.HoldingPrefix));
    }

    [Fact]
    public void A_holding_zone_may_not_overlap_an_extra_network_and_a_device_sits_on_one_list()
    {
        var c = On(Laptop);
        c.ExtraNetworks.Add(new ExtraNetwork { Name = "Cameras", Address = "10.99.0.254", Prefix = 24 });
        c.ZeroTrust.Blocked = [new BlockedDevice { Mac = Laptop }];
        var issues = ConfigValidator.Validate(c);
        Assert.Contains(issues, i => i.Message.Contains("extra network \"Cameras\""));
        Assert.Contains(issues, i => i.Message.Contains("twice"));
    }

    [Fact]
    public void Switching_on_approves_everything_already_known_but_not_waiting_or_blocked_devices()
    {
        var c = Sample();
        c.Names.Add(new DeviceName { Mac = "aa:bb:cc:00:00:02", Name = "Gran tablet" });
        c.Access.Add(new DeviceAccess { Mac = "aa:bb:cc:00:00:03", Name = "Console" });
        c.ZeroTrust.Blocked = [new BlockedDevice { Mac = "aa:bb:cc:00:00:09" }];
        c.ZeroTrust.Enabled = true;
        DhcpLease[] leases =
        [
            new(DateTimeOffset.MaxValue, Laptop, "192.168.50.100", "laptop"),
            new(DateTimeOffset.MaxValue, Stranger, "10.99.0.100", "stranger"),
            new(DateTimeOffset.MaxValue, "aa:bb:cc:00:00:09", "192.168.50.101", "blocked"),
        ];
        var known = ZeroTrustPlan.KnownDevices(c, leases, ["AA:BB:CC:00:00:04"], DateTimeOffset.UnixEpoch);

        Assert.Equal(["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03", "aa:bb:cc:00:00:04", Nas], known.Select(k => k.Mac));
        Assert.Equal("Gran tablet", known.Single(k => k.Mac == "aa:bb:cc:00:00:02").Name);
        Assert.Equal("laptop", known.Single(k => k.Mac == Laptop).Name);
    }

    [Fact]
    public void What_a_waiting_device_tried_is_read_from_the_kernels_list()
    {
        // Captured from nftables 1.1.3 on Debian 13.
        const string json = """{"nftables": [{"metainfo": {"version": "1.1.3", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "held_flows", "table": "palisade", "type": ["ether_addr", "ipv4_addr", "inet_proto", "inet_service"], "elem": [{"elem": {"val": {"concat": ["02:00:00:00:00:aa", "192.168.50.1", "udp", 53]}, "expires": 604798, "counter": {"packets": 1, "bytes": 31}}}, {"elem": {"val": {"concat": ["02:00:00:00:00:aa", "192.168.50.1", "tcp", 443]}, "expires": 604796, "counter": {"packets": 2, "bytes": 120}}}]}}]}""";
        var flows = ZeroTrustPlan.ParseFlows(json);
        Assert.Equal([(Stranger, "192.168.50.1", "udp", 53, 1L), (Stranger, "192.168.50.1", "tcp", 443, 2L)], flows);
        Assert.Empty(ZeroTrustPlan.ParseFlows("not json"));
    }

    [Fact]
    public void Attempts_add_up_across_reloads_and_decided_devices_leave_the_list()
    {
        var z = On().ZeroTrust;
        var tracker = new HeldTracker();
        var t0 = DateTimeOffset.UnixEpoch;
        var lease = new DhcpLease(t0.AddMinutes(2), Stranger, "10.99.0.100", "android-7f3a");

        Assert.True(tracker.Record(t0, [(Stranger, "1.1.1.1", "tcp", 443, 5)], [lease], z));
        // The kernel's count grew by 3, then the rules were reloaded and it started again at 2.
        tracker.Record(t0.AddSeconds(15), [(Stranger, "1.1.1.1", "tcp", 443, 8)], [lease], z);
        tracker.Record(t0.AddSeconds(30), [(Stranger, "1.1.1.1", "tcp", 443, 2)], [lease], z);
        var held = Assert.Single(tracker.Report());
        Assert.Equal((10L, "10.99.0.100", "android-7f3a"), (held.Attempts, held.Address, held.Hostname));
        Assert.Equal(10, Assert.Single(held.Flows).Packets);

        z.Approved.Add(new ApprovedDevice { Mac = Stranger });
        Assert.True(tracker.Record(t0.AddMinutes(1), [], [], z));
        Assert.Empty(tracker.Report());
    }

    [Fact]
    public void A_device_not_seen_for_a_week_is_forgotten()
    {
        var z = On().ZeroTrust;
        var tracker = new HeldTracker();
        tracker.Record(DateTimeOffset.UnixEpoch, [(Stranger, "1.1.1.1", "udp", 53, 1)], [], z);
        tracker.Record(DateTimeOffset.UnixEpoch + ZeroTrustPlan.Kept + TimeSpan.FromMinutes(1), [], [], z);
        Assert.Empty(tracker.Report());
    }

    // The engine owns the lists.

    private sealed class Platform(params DhcpLease[] leases) : ISystemPlatform
    {
        public List<string> Log { get; } = [];
        public Task<IReadOnlyList<string>> CheckAsync(FirewallConfig config, GeneratedFiles files, CancellationToken ct) => Task.FromResult<IReadOnlyList<string>>([]);
        public Task ApplyAsync(FirewallConfig config, GeneratedFiles files, CancellationToken ct) { Log.Add($"apply:{config.ZeroTrust.Enabled}:{config.ZeroTrust.Approved.Count}"); return Task.CompletedTask; }
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
        public Task<SystemStatus> GetStatusAsync(FirewallConfig active, CancellationToken ct) => Task.FromResult(new SystemStatus());
        public Task<IReadOnlyList<DhcpLease>> GetLeasesAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<DhcpLease>>(leases);
        public Task<UsageReport> GetUsageAsync(CancellationToken ct) => Task.FromResult(new UsageReport());
        public Task SetAccessAsync(IReadOnlyList<DeviceAccess> access, CancellationToken ct) => Task.CompletedTask;
        public Task<WifiStatus> GetWifiAsync(CancellationToken ct) => Task.FromResult(new WifiStatus());
        public Task<ApplyResult> SetWifiAsync(WifiRequest request, CancellationToken ct) => Task.FromResult(new ApplyResult { Ok = true });
        public Task SetApprovalsAsync(FirewallConfig live, CancellationToken ct) { Log.Add($"live:{string.Join(",", live.ZeroTrust.Approved.Select(a => a.Mac))}"); return Task.CompletedTask; }
        public Task<IReadOnlyList<string>> GetNeighboursAsync(FirewallConfig live, CancellationToken ct) => Task.FromResult<IReadOnlyList<string>>(["aa:bb:cc:00:00:05"]);
    }

    private static async Task<FirewallEngine> SetUpAsync(Platform platform)
    {
        var engine = new FirewallEngine(platform, Directory.CreateTempSubdirectory("palisade-zt").FullName, TimeSpan.FromSeconds(30));
        await engine.InitializeAsync();
        Assert.True((await engine.ApplyAsync(Sample())).Ok);
        await engine.ConfirmAsync();
        return engine;
    }

    [Fact]
    public async Task Switching_on_waits_for_confirmation_and_approves_what_is_here()
    {
        var platform = new Platform(new DhcpLease(DateTimeOffset.MaxValue, Laptop, "192.168.50.100", "laptop"));
        using var engine = await SetUpAsync(platform);

        var result = await engine.SetZeroTrustAsync(new ZeroTrustRequest { Enabled = true, HoldingAddress = "10.99.0.1", HoldingPrefix = 24 });
        Assert.True(result.Ok);
        Assert.True(result.ConfirmWithinSeconds > 0);
        var config = await engine.GetConfigAsync();
        Assert.True(config.ZeroTrust.Enabled);
        Assert.Equal([Laptop, "aa:bb:cc:00:00:05", Nas], config.ZeroTrust.Approved.Select(a => a.Mac));
    }

    [Fact]
    public async Task A_save_from_a_screen_without_zero_trust_can_not_switch_it_off_or_undo_approvals()
    {
        using var engine = await SetUpAsync(new Platform());
        await engine.SetZeroTrustAsync(new ZeroTrustRequest { Enabled = true });
        await engine.ConfirmAsync();
        Assert.True((await engine.ChangeApprovalAsync(new ApprovalChange { Action = ApprovalAction.Approve, Mac = Stranger, Name = "Phone" })).Ok);

        // Like the v1.3 app, or a tab opened before: a whole config with an empty Zero Trust section.
        var old = Sample();
        old.LanAddress = "192.168.50.1";
        Assert.True((await engine.ApplyAsync(old)).Ok);
        await engine.ConfirmAsync();

        var config = await engine.GetConfigAsync();
        Assert.True(config.ZeroTrust.Enabled);
        Assert.Contains(config.ZeroTrust.Approved, a => a.Mac == Stranger && a.Name == "Phone");
    }

    [Fact]
    public async Task Letting_a_device_in_is_immediate_but_taking_access_away_waits_for_confirmation()
    {
        var platform = new Platform();
        using var engine = await SetUpAsync(platform);
        await engine.SetZeroTrustAsync(new ZeroTrustRequest { Enabled = true });
        await engine.ConfirmAsync();

        var approve = await engine.ChangeApprovalAsync(new ApprovalChange { Action = ApprovalAction.Approve, Mac = "02:00:00:00:00:AA" });
        Assert.True(approve.Ok);
        Assert.Equal(0, approve.ConfirmWithinSeconds);
        Assert.Contains($"live:aa:bb:cc:00:00:05,{Nas},{Stranger}", platform.Log);
        Assert.Null((await engine.GetStatusAsync()).PendingSecondsLeft);

        // Blocking a device that is still waiting keeps it out, which takes nothing away: also immediate.
        Assert.Equal(0, (await engine.ChangeApprovalAsync(new ApprovalChange { Action = ApprovalAction.Block, Mac = "02:00:00:00:00:bb" })).ConfirmWithinSeconds);

        var remove = await engine.ChangeApprovalAsync(new ApprovalChange { Action = ApprovalAction.Remove, Mac = Stranger });
        Assert.True(remove.ConfirmWithinSeconds > 0);
        Assert.DoesNotContain((await engine.GetConfigAsync()).ZeroTrust.Approved, a => a.Mac == Stranger);
        // Not confirmed: the device is approved again.
        await engine.RevertAsync();
        Assert.Contains((await engine.GetConfigAsync()).ZeroTrust.Approved, a => a.Mac == Stranger);
    }

    [Fact]
    public async Task An_approval_made_while_another_change_waits_survives_that_change_being_undone()
    {
        using var engine = await SetUpAsync(new Platform());
        await engine.SetZeroTrustAsync(new ZeroTrustRequest { Enabled = true });
        await engine.ConfirmAsync();

        var other = Sample();
        other.Dhcp.LeaseHours = 6;
        await engine.ApplyAsync(other);
        await engine.ChangeApprovalAsync(new ApprovalChange { Action = ApprovalAction.Approve, Mac = Stranger });
        await engine.RevertAsync();

        Assert.Contains((await engine.GetConfigAsync()).ZeroTrust.Approved, a => a.Mac == Stranger);
    }

    [Fact]
    public async Task With_the_mode_off_there_is_nothing_to_approve()
    {
        using var engine = await SetUpAsync(new Platform());
        var result = await engine.ChangeApprovalAsync(new ApprovalChange { Action = ApprovalAction.Approve, Mac = Stranger });
        Assert.False(result.Ok);
        Assert.Contains("off", result.Issues[0].Message);
    }

    private static string[] Chain(string nft, string name)
    {
        var lines = nft.Split('\n');
        var start = Array.FindIndex(lines, l => l.Trim() == $"chain {name} {{");
        var end = Array.FindIndex(lines, start + 1, l => l.Trim() == "}");
        return [.. lines[(start + 2)..end].Select(l => l.Trim())];
    }

    private static int Line(string[] chain, string startsWith)
    {
        var i = Array.FindIndex(chain, l => l.StartsWith(startsWith, StringComparison.Ordinal) || l.Contains(startsWith));
        Assert.True(i >= 0, $"No line with: {startsWith}");
        return i;
    }
}
