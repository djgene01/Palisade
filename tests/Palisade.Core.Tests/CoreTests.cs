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
        // The only hardware-address rule is the pause rule, and its set starts out empty.
        Assert.Single(files.Nftables.Split('\n'), line => line.Contains("ether saddr"));
        Assert.Contains("set paused { type ether_addr; }", files.Nftables);
        Assert.Empty(c.Access);
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
    public void Usage_is_counted_per_home_address_without_deciding_anything()
    {
        var text = ConfigRenderer.Nftables(Sample());

        Assert.Contains("table inet palisade_usage {", text);
        Assert.Contains("type filter hook forward priority -10; policy accept;", text);
        Assert.Contains("iifname \"enp2s0\" oifname \"enp1s0\" ip saddr 192.168.50.0/24 update @sent { ip saddr }", text);
        Assert.Contains("iifname \"enp1s0\" oifname \"enp2s0\" ip daddr 192.168.50.0/24 update @received { ip daddr }", text);
        var usage = text[text.IndexOf("table inet palisade_usage", StringComparison.Ordinal)..];
        Assert.DoesNotContain("drop", usage);
        Assert.DoesNotContain("reject", usage);
    }

    [Fact]
    public void Usage_tracker_survives_counter_resets_and_forgets_old_hours()
    {
        var start = new DateTimeOffset(2026, 1, 1, 10, 0, 0, TimeSpan.Zero);
        var tracker = new UsageTracker(start);
        static Dictionary<string, (long, long)> At(long down, long up) => new() { ["192.168.50.20"] = (down, up) };

        // Whatever was counted before the first reading is of unknown age and is left out.
        tracker.Record(start, At(5_000_000, 1_000_000));
        Assert.Empty(tracker.Report(start).Devices);

        tracker.Record(start.AddSeconds(10), At(5_100_000, 1_020_000));
        var device = Assert.Single(tracker.Report(start.AddSeconds(10)).Devices);
        Assert.Equal((100_000, 20_000), (device.DownBytes, device.UpBytes));
        Assert.Equal(10_000, device.DownRate, 3);
        Assert.Equal(2_000, device.UpRate, 3);

        // The rules were reloaded: the kernel counts from zero again, and nothing may go negative or be lost.
        tracker.Record(start.AddSeconds(20), At(30_000, 0));
        device = Assert.Single(tracker.Report(start.AddSeconds(20)).Devices);
        Assert.Equal((130_000, 20_000), (device.DownBytes, device.UpBytes));

        // A second device that appears later is counted from its first byte, and the busiest is listed first.
        var both = At(30_000, 0);
        both["192.168.50.21"] = (900_000, 5);
        tracker.Record(start.AddSeconds(30), both);
        var report = tracker.Report(start.AddSeconds(30));
        Assert.Equal(["192.168.50.21", "192.168.50.20"], report.Devices.Select(d => d.Address));
        Assert.Equal(start, report.Since);
        Assert.Equal(0, report.Devices[1].DownRate);

        // A day later the old hours have dropped out of the total.
        var later = start.AddHours(25);
        tracker.Record(later, new Dictionary<string, (long, long)>());
        Assert.Empty(tracker.Report(later).Devices);
        Assert.Equal(later.AddHours(-24), tracker.Report(later).Since);
    }

    [Fact]
    public void Usage_counters_are_read_from_nft_json()
    {
        const string json = """
            {"nftables": [{"metainfo": {"version": "1.1.3"}}, {"set": {"family": "inet", "name": "received", "table": "palisade_usage", "type": "ipv4_addr",
            "elem": [{"elem": {"val": "192.168.88.156", "expires": 86399, "counter": {"packets": 5387, "bytes": 5871052}}}, "192.168.88.9",
            {"elem": {"val": "not-an-address", "counter": {"packets": 1, "bytes": 1}}}], "stmt": [{"counter": null}]}}]}
            """;

        var parsed = UsageParser.ParseSet(json);
        Assert.Equal(5871052, Assert.Single(parsed).Value);
        Assert.Equal("192.168.88.156", parsed.Keys.Single());
        Assert.Empty(UsageParser.ParseSet("Error: No such file or directory"));
        Assert.Empty(UsageParser.ParseSet("{\"nftables\": [{\"set\": {\"name\": \"sent\"}}]}"));
    }

    [Fact]
    public void Pause_rule_comes_before_established_traffic_is_let_through()
    {
        var text = ConfigRenderer.Nftables(Sample());
        var forward = text[text.IndexOf("chain forward", StringComparison.Ordinal)..];

        Assert.Contains("iifname \"enp2s0\" ether saddr @paused counter reject", forward);
        Assert.True(forward.IndexOf("@paused", StringComparison.Ordinal) < forward.IndexOf("ct state established", StringComparison.Ordinal));
    }

    [Fact]
    public void Off_times_follow_the_clock_across_midnight_and_the_week()
    {
        var device = new DeviceAccess
        {
            Mac = "aa:bb:cc:dd:ee:20",
            Name = "Tablet",
            OffTimes =
            {
                new OffTime { Days = { DayOfWeek.Sunday, DayOfWeek.Monday }, From = "21:00", To = "07:00" },
                new OffTime { Days = { DayOfWeek.Wednesday }, From = "15:00", To = "16:30" },
                new OffTime { Days = { DayOfWeek.Friday }, From = "10:00", To = "10:00" },
            },
        };
        // 1 November 2026 is a Sunday.
        bool Off(int day, int hour, int minute) => AccessPlan.CurrentOffTime(device, new DateTime(2026, 11, day, hour, minute, 0)) is not null;

        Assert.False(Off(1, 20, 59));
        Assert.True(Off(1, 21, 0));
        Assert.True(Off(2, 6, 59));   // Monday morning, from Sunday night
        Assert.False(Off(2, 7, 0));
        Assert.True(Off(2, 23, 30));  // Monday night
        Assert.True(Off(3, 3, 0));    // Tuesday morning, from Monday night
        Assert.False(Off(3, 22, 0));  // Tuesday night is not listed
        Assert.False(Off(1, 6, 0));   // Sunday morning: Saturday night is not listed
        Assert.True(Off(4, 15, 0));
        Assert.True(Off(4, 16, 29));
        Assert.False(Off(4, 16, 30));
        Assert.False(Off(6, 10, 0));  // equal start and end never switches anything off
    }

    [Fact]
    public void Timed_pause_ends_by_itself_and_an_open_pause_does_not()
    {
        var now = new DateTimeOffset(2026, 11, 2, 12, 0, 0, TimeSpan.FromHours(2));
        var timed = new DeviceAccess { Mac = "aa:bb:cc:dd:ee:21", Name = "Console", Paused = true, PausedUntil = now.AddMinutes(30) };
        var open = new DeviceAccess { Mac = "aa:bb:cc:dd:ee:20", Name = "Tablet", Paused = true };
        var free = new DeviceAccess { Mac = "aa:bb:cc:dd:ee:22", Name = "Laptop" };

        Assert.Equal(["aa:bb:cc:dd:ee:20", "aa:bb:cc:dd:ee:21"], AccessPlan.OffNow([timed, open, free], now, now.DateTime));
        Assert.Equal(["aa:bb:cc:dd:ee:20"], AccessPlan.OffNow([timed, open, free], now.AddMinutes(30), now.DateTime));
    }

    [Fact]
    public void Paused_set_script_is_one_step_and_refuses_unsafe_addresses()
    {
        Assert.Equal("flush set inet palisade paused\n", AccessPlan.SetScript([]));
        Assert.Equal("flush set inet palisade paused\nadd element inet palisade paused { aa:bb:cc:dd:ee:20, aa:bb:cc:dd:ee:21 }\n",
            AccessPlan.SetScript(["aa:bb:cc:dd:ee:20", "aa:bb:cc:dd:ee:21"]));
        Assert.Throws<InvalidOperationException>(() => AccessPlan.SetScript(["aa:bb:cc:dd:ee:20 }\nflush ruleset\n"]));
        Assert.Throws<InvalidOperationException>(() => AccessPlan.SetScript(["AA:BB:CC:DD:EE:20"]));
    }

    [Fact]
    public void Access_validation_catches_common_mistakes()
    {
        var bad = new List<DeviceAccess>
        {
            new() { Mac = "aa:bb:cc:dd:ee:20", Name = "Tablet", OffTimes = { new OffTime { Days = { DayOfWeek.Monday }, From = "9:00", To = "25:00" } } },
            new() { Mac = "aa:bb:cc:dd:ee:20", Name = "Tablet again" },
            new() { Mac = "aa:bb:cc:dd:ee:23", Name = "No days", OffTimes = { new OffTime { From = "21:00", To = "07:00" } } },
            new() { Mac = "aa:bb:cc:dd:ee:24", Name = "Same", OffTimes = { new OffTime { Days = { DayOfWeek.Monday }, From = "08:00", To = "08:00" } } },
            new() { Mac = "aa:bb:cc:dd:ee:25", Name = "bad\nname" },
        };
        var fields = AccessPlan.Validate(bad).Select(i => i.Field).Distinct().ToList();

        Assert.Equal(4, fields.Count);
        Assert.Empty(AccessPlan.Validate([new() { Mac = "aa:bb:cc:dd:ee:20", Name = "Tablet", OffTimes = { new OffTime { Days = { DayOfWeek.Monday } } } }]));
        var c = Sample();
        c.Access.AddRange(bad);
        Assert.NotEmpty(ConfigValidator.Validate(c));
    }

    [Fact]
    public void Maintenance_port_reaches_the_firewall_and_nothing_else()
    {
        var c = Sample();
        c.MaintenanceInterface = "wlp3s0";
        Assert.Empty(ConfigValidator.Validate(c));
        var text = ConfigRenderer.Nftables(c);

        Assert.Contains("iifname \"wlp3s0\" tcp dport { 22, 8080, 8081 } accept comment \"manage from maintenance port\"", text);
        // It appears once, in the input chain: nothing is forwarded to or from it, and it gets no NAT.
        Assert.Single(text.Split('\n'), line => line.Contains("wlp3s0"));

        c.MaintenanceInterface = c.LanInterface;
        Assert.Contains("MaintenanceInterface", ConfigValidator.Validate(c).Select(i => i.Field));
        c.MaintenanceInterface = "wl p\"; drop";
        Assert.NotEmpty(ConfigValidator.Validate(c));
        Assert.Throws<InvalidOperationException>(() => ConfigRenderer.Nftables(c));
        Assert.DoesNotContain("maintenance", ConfigRenderer.Nftables(Sample()));
    }

    [Fact]
    public void Each_port_answers_only_for_its_own_address()
    {
        var sysctl = ConfigRenderer.Render(Sample()).Sysctl;
        Assert.Contains("net.ipv4.ip_forward=1\n", sysctl);
        Assert.Contains("net.ipv4.conf.all.arp_ignore=1\n", sysctl);
        Assert.Contains("net.ipv4.conf.all.arp_announce=2\n", sysctl);
    }

    [Fact]
    public void Extra_network_is_reachable_from_home_but_kept_off_the_internet()
    {
        var c = Sample();
        c.ExtraNetworks.Add(new() { Name = "Cameras", Address = "192.168.10.254", Prefix = 24 });
        Assert.Empty(ConfigValidator.Validate(c));

        var lan = c.LanInterface;
        var text = ConfigRenderer.Nftables(c);
        Assert.Contains($"iifname \"{lan}\" oifname \"{lan}\" ip saddr 192.168.50.0/24 ip daddr 192.168.10.0/24 accept", text);
        Assert.Contains($"oifname \"{lan}\" ip saddr 192.168.50.0/24 ip daddr 192.168.10.0/24 masquerade", text);
        Assert.Contains("ip saddr 192.168.10.0/24 counter reject", text);
        Assert.True(text.IndexOf("ip saddr 192.168.10.0/24 counter reject", StringComparison.Ordinal) < text.IndexOf("home network to internet", StringComparison.Ordinal));
        Assert.Contains($"    address 192.168.50.1/24\n    up ip addr add 192.168.10.254/24 dev {lan}\n", ConfigRenderer.LanInterface(c));

        c.ExtraNetworks[0].InternetAccess = true;
        Assert.DoesNotContain("ip saddr 192.168.10.0/24 counter reject", ConfigRenderer.Nftables(c));
        Assert.DoesNotContain("192.168.10.", ConfigRenderer.Nftables(Sample()));
    }

    [Theory]
    [InlineData("192.168.50.9", 24)]   // inside the home network
    [InlineData("192.168.10.0", 24)]   // the range's own reserved address
    [InlineData("8.8.8.1", 24)]        // not a private range
    [InlineData("192.168.10.254", 8)]  // size out of bounds
    [InlineData("192.168.0.1", 16)]    // swallows the home network
    public void Extra_network_with_a_bad_range_is_refused(string address, int prefix)
    {
        var c = Sample();
        c.ExtraNetworks.Add(new() { Name = "Cameras", Address = address, Prefix = prefix });
        Assert.NotEmpty(ConfigValidator.Validate(c));
    }

    [Fact]
    public void Two_extra_networks_may_not_overlap()
    {
        var c = Sample();
        c.ExtraNetworks.Add(new() { Name = "Cameras", Address = "192.168.10.254", Prefix = 24 });
        c.ExtraNetworks.Add(new() { Name = "Printers", Address = "192.168.10.1", Prefix = 24 });
        Assert.Contains(ConfigValidator.Validate(c), i => i.Message.Contains("overlaps"));
    }

    [Fact]
    public void Only_the_makers_half_of_an_address_is_looked_up()
    {
        Assert.Equal("7cf666", Maker.Prefix("7C-F6-66-12-34-56"));
        Assert.Null(Maker.Prefix("not an address"));
        Assert.False(Maker.IsMadeUp("7c:f6:66:12:34:56"));
        Assert.True(Maker.IsMadeUp("da:a1:19:00:00:01"));
        Assert.Equal("Tuya Smart Inc.", Maker.Clean("  Tuya Smart\u0007 Inc. "));
        Assert.Equal(60, Maker.Clean(new string('x', 200)).Length);
    }

    [Fact]
    public void Wired_internet_port_asks_for_an_address()
    {
        Assert.Equal("allow-hotplug enp1s0\niface enp1s0 inet dhcp\n", ConfigRenderer.Render(Sample()).WanInterface.Split('\n', 2)[1]);
    }

    [Fact]
    public void Wifi_settings_file_holds_only_hex_whatever_is_typed()
    {
        // The published example for this key derivation: network "IEEE", password "password".
        var conf = WifiPlan.SupplicantConf(new WifiRequest { Ssid = "IEEE", Passphrase = "password" });
        Assert.Contains("    ssid=49454545\n", conf);
        Assert.Contains("    psk=f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e\n", conf);

        var tricky = WifiPlan.SupplicantConf(new WifiRequest { Ssid = "Caf\u00e9 \"x\" }", Passphrase = "pass\"word}#1" });
        Assert.DoesNotContain("Caf", tricky);
        Assert.DoesNotContain("word", tricky);
        Assert.Equal(6, tricky.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);

        Assert.Contains("key_mgmt=NONE", WifiPlan.SupplicantConf(new WifiRequest { Ssid = "Open cafe" }));
        Assert.Throws<InvalidOperationException>(() => WifiPlan.SupplicantConf(new WifiRequest { Ssid = "a\nb", Passphrase = "password" }));
        Assert.NotEmpty(WifiPlan.Validate(new WifiRequest { Ssid = "Home", Passphrase = "short" }));
        Assert.NotEmpty(WifiPlan.Validate(new WifiRequest { Ssid = "Home", Passphrase = "pass\nword123" }));
        Assert.NotEmpty(WifiPlan.Validate(new WifiRequest { Ssid = "", Passphrase = "password" }));
        Assert.NotEmpty(WifiPlan.Validate(new WifiRequest { Ssid = new string('x', 33), Passphrase = "password" }));
        Assert.Throws<InvalidOperationException>(() => WifiPlan.WifiStanza("wlan0\npost-up reboot"));
    }

    [Fact]
    public void Taking_over_a_port_removes_only_that_port_from_debians_file()
    {
        const string file = """
            # This file describes the network interfaces available on your system

            source /etc/network/interfaces.d/*

            # The loopback network interface
            auto lo
            iface lo inet loopback

            # The primary network interface
            allow-hotplug wlp58s0
            iface wlp58s0 inet dhcp
            	wpa-ssid Example
            	wpa-psk  secretsecret

            allow-hotplug enp1s0
            iface enp1s0 inet dhcp
            """;

        Assert.True(WifiPlan.IsDefined(file, "wlp58s0"));
        Assert.False(WifiPlan.IsDefined(file, "wlp58s"));
        var stripped = WifiPlan.StripStanza(file, "wlp58s0");

        Assert.DoesNotContain("wlp58s0", stripped);
        Assert.DoesNotContain("wpa-", stripped);
        Assert.Contains("iface lo inet loopback", stripped);
        Assert.Contains("source /etc/network/interfaces.d/*", stripped);
        Assert.Contains("allow-hotplug enp1s0\niface enp1s0 inet dhcp", stripped.Replace("\r", ""));
        Assert.Equal(stripped, WifiPlan.StripStanza(stripped, "wlp58s0"));
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
        public Task<UsageReport> GetUsageAsync(CancellationToken ct) => Task.FromResult(new UsageReport());
        public Task<WifiStatus> GetWifiAsync(CancellationToken ct) => Task.FromResult(new WifiStatus());
        public Task<ApplyResult> SetWifiAsync(WifiRequest request, CancellationToken ct) => Task.FromResult(new ApplyResult { Ok = true });

        public Task SetAccessAsync(IReadOnlyList<DeviceAccess> access, CancellationToken ct)
        {
            Log.Add($"access:{string.Join(",", access.Where(a => a.Paused).Select(a => a.Mac))}");
            return Task.CompletedTask;
        }
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
    public async Task Pause_is_saved_at_once_and_survives_other_saves_and_undo()
    {
        var dir = TempDir();
        var platform = new FakePlatform();
        const string mac = "aa:bb:cc:dd:ee:20";
        using (var engine = new FirewallEngine(platform, dir, TimeSpan.FromSeconds(30)))
        {
            await engine.InitializeAsync();
            await engine.ApplyAsync(Config());
            await engine.ConfirmAsync();

            Assert.True((await engine.SetAccessAsync([new DeviceAccess { Mac = mac, Name = "Tablet", Paused = true }])).Ok);
            Assert.Null((await engine.GetStatusAsync()).PendingSecondsLeft);

            // A page that loaded before the pause saves something else: the pause must not be wiped,
            // neither while that change is pending nor when it is undone.
            var stale = Config("192.168.60.1");
            stale.Dhcp.RangeStart = "192.168.60.100";
            stale.Dhcp.RangeEnd = "192.168.60.200";
            Assert.True((await engine.ApplyAsync(stale)).Ok);
            Assert.Equal(mac, Assert.Single((await engine.GetConfigAsync()).Access).Mac);
            await engine.RevertAsync();
            Assert.True(Assert.Single((await engine.GetConfigAsync()).Access).Paused);

            Assert.False((await engine.SetAccessAsync([new DeviceAccess { Mac = "nonsense", Name = "Tablet" }])).Ok);

            // Names follow the same path: saved at once, kept through other saves, never part of a pending change.
            Assert.True((await engine.SetNamesAsync([new DeviceName { Mac = mac, Name = "Emma's iPad (blue)" }])).Ok);
            Assert.Null((await engine.GetStatusAsync()).PendingSecondsLeft);
            Assert.True((await engine.ApplyAsync(Config())).Ok);
            await engine.ConfirmAsync();
            Assert.False((await engine.SetNamesAsync([new DeviceName { Mac = mac, Name = "two\nlines" }])).Ok);
            Assert.False((await engine.SetNamesAsync([new DeviceName { Mac = mac, Name = "" }])).Ok);
            Assert.False((await engine.SetNamesAsync([new DeviceName { Mac = mac, Name = new string('x', 41) }])).Ok);
            Assert.False((await engine.SetNamesAsync([new DeviceName { Mac = mac, Name = "A" }, new DeviceName { Mac = mac, Name = "B" }])).Ok);
            Assert.Contains($"access:{mac}", platform.Log);
        }

        using var restarted = new FirewallEngine(platform, dir, TimeSpan.FromSeconds(30));
        await restarted.InitializeAsync();
        Assert.True(Assert.Single((await restarted.GetConfigAsync()).Access).Paused);
        Assert.Equal("Emma's iPad (blue)", Assert.Single((await restarted.GetConfigAsync()).Names).Name);
        // A name is for people only: whatever it contains, it never reaches a generated file.
        var files = ConfigRenderer.Render(await restarted.GetConfigAsync());
        Assert.DoesNotContain("Emma", files.Nftables + files.Dnsmasq);
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
