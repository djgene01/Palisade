using Palisade.Core;

namespace Palisade.Core.Tests;

public class NamesTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 19, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Later = Now.AddHours(1);

    private static NameCandidate Device(string mac, string given = "", string own = "", string maker = "", string address = "192.168.50.100") =>
        new(mac, address, given, own, maker);

    [Theory]
    [InlineData("Gran's tablet", "grans-tablet")]
    [InlineData("  Living Room TV!! ", "living-room-tv")]
    [InlineData("Café-Printer", "cafe-printer")]
    [InlineData("android_7f3a", "android-7f3a")]
    [InlineData("12345", "")]
    [InlineData("---", "")]
    [InlineData(null, "")]
    [InlineData("a-very-long-name-that-goes-on-and-on-and-on-forever", "a-very-long-name-that-goes-on-and-on-and")]
    public void Names_are_made_safe_for_dns(string? text, string expected) => Assert.Equal(expected, NamePlan.Slug(text));

    [Fact]
    public void The_owners_name_wins_then_the_devices_own_then_its_maker_with_a_tag()
    {
        Assert.Equal("grans-tablet", NamePlan.Base(Device("00:16:6c:00:3f:2a", "Gran's tablet", "android-1234", "Samsung Electronics")));
        Assert.Equal("android-1234", NamePlan.Base(Device("00:16:6c:00:3f:2a", "", "android-1234", "Samsung Electronics")));
        Assert.Equal("samsung-3f2a", NamePlan.Base(Device("00:16:6c:00:3f:2a", "", "", "Samsung Electronics")));
        Assert.Equal("device-3f2a", NamePlan.Base(Device("00:16:6c:00:3f:2a")));
        // A made-up hardware address says nothing about the maker, whatever a lookup claims.
        Assert.Equal("device-3f2a", NamePlan.Base(Device("02:bb:cc:00:3f:2a", "", "", "Samsung Electronics")));
    }

    [Fact]
    public void A_second_device_with_the_same_name_gets_a_number_and_the_first_keeps_its_name_for_good()
    {
        var book = new NameBook();
        book.Assign([Device("aa:00:00:00:00:01", own: "iphone")], Now);
        book.Assign([Device("aa:00:00:00:00:02", own: "iphone"), Device("aa:00:00:00:00:01", own: "iphone")], Later);
        Assert.Equal("iphone", book.NameOf("aa:00:00:00:00:01"));
        Assert.Equal("iphone-2", book.NameOf("aa:00:00:00:00:02"));

        // The first one goes away for a while; the second never takes its name.
        book.Assign([Device("aa:00:00:00:00:02", own: "iphone")], Later.AddDays(3));
        Assert.Equal("iphone-2", book.NameOf("aa:00:00:00:00:02"));

        // Across a restart, the same.
        var reloaded = new NameBook(book.Export());
        reloaded.Assign([Device("aa:00:00:00:00:02", own: "iphone"), Device("aa:00:00:00:00:01", own: "iphone")], Later.AddDays(4));
        Assert.Equal("iphone", reloaded.NameOf("aa:00:00:00:00:01"));
        Assert.Equal("iphone-2", reloaded.NameOf("aa:00:00:00:00:02"));
    }

    [Theory]
    [InlineData("palisade")]
    [InlineData("wpad")]
    [InlineData("localhost")]
    public void A_device_can_never_take_the_firewalls_name_or_one_programs_look_up_by_themselves(string claimed)
    {
        var book = new NameBook();
        book.Assign([Device("aa:00:00:00:00:01", own: claimed)], Now);
        Assert.Equal($"{claimed}-2", book.NameOf("aa:00:00:00:00:01"));
        // Nor can it sneak in through a damaged saved file.
        Assert.Null(new NameBook([new SavedName("aa:00:00:00:00:01", claimed, claimed, Now)]).NameOf("aa:00:00:00:00:01"));
    }

    [Fact]
    public void The_owners_name_takes_precedence_over_what_another_device_calls_itself()
    {
        var book = new NameBook();
        // A phone happened to call itself "nas" first.
        book.Assign([Device("aa:00:00:00:00:01", own: "nas")], Now);
        Assert.Equal("nas", book.NameOf("aa:00:00:00:00:01"));
        // The owner names the real NAS "NAS": it gets "nas", the phone moves to "nas-2".
        book.Assign([Device("aa:00:00:00:00:02", given: "NAS", own: "diskstation"), Device("aa:00:00:00:00:01", own: "nas")], Later);
        Assert.Equal("nas", book.NameOf("aa:00:00:00:00:02"));
        Assert.Equal("nas-2", book.NameOf("aa:00:00:00:00:01"));
        // It stays that way, and two names the owner gave never displace each other.
        book.Assign([Device("aa:00:00:00:00:03", given: "NAS"), Device("aa:00:00:00:00:02", given: "NAS", own: "diskstation"), Device("aa:00:00:00:00:01", own: "nas")], Later.AddHours(1));
        Assert.Equal("nas", book.NameOf("aa:00:00:00:00:02"));
        Assert.Equal("nas-3", book.NameOf("aa:00:00:00:00:03"));
        Assert.Equal("nas-2", book.NameOf("aa:00:00:00:00:01"));
    }

    [Fact]
    public void The_owner_may_call_a_device_router_but_a_device_may_not_call_itself_that()
    {
        var book = new NameBook();
        book.Assign([Device("aa:00:00:00:00:01", own: "router"), Device("aa:00:00:00:00:02", given: "Router")], Now);
        Assert.Equal("router", book.NameOf("aa:00:00:00:00:02"));
        Assert.Equal("router-2", book.NameOf("aa:00:00:00:00:01"));
        // The firewall's own name is out of reach even for the owner.
        book.Assign([Device("aa:00:00:00:00:03", given: "Palisade")], Later);
        Assert.Equal("palisade-2", book.NameOf("aa:00:00:00:00:03"));
    }

    [Fact]
    public void The_main_name_server_does_not_serve_the_machines_own_hosts_file()
    {
        Assert.Contains("bind-dynamic\nno-hosts\n", ConfigRenderer.Dnsmasq(new FirewallConfig { LanInterface = "enp2s0" }));
    }

    [Fact]
    public void Renaming_a_device_renames_it_and_frees_the_old_name()
    {
        var book = new NameBook();
        book.Assign([Device("aa:00:00:00:00:01", own: "laptop")], Now);
        book.Assign([Device("aa:00:00:00:00:01", given: "Dad's laptop", own: "laptop")], Later);
        Assert.Equal("dads-laptop", book.NameOf("aa:00:00:00:00:01"));
        book.Assign([Device("aa:00:00:00:00:02", own: "laptop")], Later);
        Assert.Equal("laptop", book.NameOf("aa:00:00:00:00:02"));
    }

    [Fact]
    public void A_device_away_for_three_months_gives_its_name_up()
    {
        var book = new NameBook();
        book.Assign([Device("aa:00:00:00:00:01", own: "tv")], Now);
        book.Assign([Device("aa:00:00:00:00:02", own: "tv")], Now + NameBook.Kept + TimeSpan.FromDays(1));
        Assert.Null(book.NameOf("aa:00:00:00:00:01"));
        Assert.Equal("tv", book.NameOf("aa:00:00:00:00:02"));
    }

    [Fact]
    public void Fixed_address_devices_are_named_even_when_away_and_waiting_ones_never()
    {
        var c = new FirewallConfig
        {
            Names = { new DeviceName { Mac = "aa:00:00:00:00:01", Name = "Gran's tablet" } },
            Dhcp = { Reservations = { new Reservation { Mac = "aa:00:00:00:00:02", Address = "192.168.50.20", Name = "nas" } } },
        };
        DhcpLease[] leases =
        [
            new(Now.AddHours(1), "aa:00:00:00:00:01", "192.168.50.101", "android-1"),
            new(Now.AddHours(-1), "aa:00:00:00:00:03", "192.168.50.103", "expired"),
            new(Now.AddHours(1), "aa:00:00:00:00:04", "10.99.0.100", "held"),
        ];
        var found = NamePlan.Candidates(c, leases, _ => null, Now);
        Assert.Equal(["aa:00:00:00:00:01", "aa:00:00:00:00:02"], found.Select(d => d.Mac).Order());
        Assert.Equal("Gran's tablet", found.Single(d => d.Mac == "aa:00:00:00:00:01").GivenName);
        Assert.Equal("192.168.50.20", found.Single(d => d.Mac == "aa:00:00:00:00:02").Address);

        c.ZeroTrust.Enabled = true;
        c.ZeroTrust.Approved = [new ApprovedDevice { Mac = "aa:00:00:00:00:02" }];
        Assert.Equal(["aa:00:00:00:00:02"], NamePlan.Candidates(c, leases, _ => null, Now).Select(d => d.Mac));
    }

    [Fact]
    public void The_names_file_holds_the_firewall_and_each_device_and_refuses_anything_unsafe()
    {
        var text = NamePlan.HostsFileText("192.168.50.1", [("192.168.50.20", "nas"), ("192.168.50.101", "grans-tablet")]);
        Assert.Equal("# Generated by Palisade. Do not edit: names change as devices come and go.\n"
            + "192.168.50.1 palisade.home.arpa palisade\n192.168.50.101 grans-tablet.home.arpa grans-tablet\n192.168.50.20 nas.home.arpa nas\n", text);
        Assert.Throws<InvalidOperationException>(() => NamePlan.HostsFileText("192.168.50.1", [("192.168.50.20", "nas\n1.2.3.4 evil")]));
        Assert.Throws<InvalidOperationException>(() => NamePlan.HostsFileText("192.168.50.1", [("not an address", "nas")]));
    }

    [Fact]
    public void Every_name_server_answers_home_names_itself_and_only_the_main_one_hands_out_the_domain()
    {
        var c = new FirewallConfig { LanInterface = "enp2s0", Filter = { Level = FilterLevel.Security } };
        c.Filter.Devices.Add(new DeviceFilter { Mac = "aa:00:00:00:00:01", Level = FilterLevel.Family });
        foreach (var instance in ConfigRenderer.DnsInstances(c))
        {
            Assert.Contains("local=/home.arpa/\n", instance.Conf);
            Assert.Contains("hostsdir=/etc/palisade/names\n", instance.Conf);
            Assert.DoesNotContain("dhcp-ignore-names", instance.Conf);
        }
        Assert.Contains("dhcp-ignore-names\n", ConfigRenderer.Dnsmasq(c));
    }
}
