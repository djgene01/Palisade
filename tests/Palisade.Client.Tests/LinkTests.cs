using Palisade.Core;

namespace Palisade.Client.Tests;

public sealed class LinkTests
{
    private const string Pin = "jS-jMyCvtjk3oLJ5Y3lJu6pgTlTl0pKG0q-gD3K5Qz0";

    [Fact]
    public void A_pairing_link_made_by_the_firewall_reads_back_exactly()
    {
        var invite = PairingLinks.Parse(AppContract.PairingLink("192.168.50.1", 8443, Pin, "0MPM8E2H"));

        Assert.Equal(new PairingInvite(new FirewallAddress("192.168.50.1", 8443, Pin), "0MPM8E2H"), invite);
        Assert.Equal(new Uri("https://192.168.50.1:8443/"), invite!.Address.BaseUri);
    }

    [Theory]
    [InlineData("https://192.168.50.1/")]
    [InlineData("palisade://other?h=192.168.50.1&p=8443&k=" + Pin + "&c=0MPM8E2H")]
    [InlineData("palisade://pair?p=8443&k=" + Pin + "&c=0MPM8E2H")]
    [InlineData("palisade://pair?h=bad host&p=8443&k=" + Pin + "&c=0MPM8E2H")]
    [InlineData("palisade://pair?h=192.168.50.1&p=99999&k=" + Pin + "&c=0MPM8E2H")]
    [InlineData("palisade://pair?h=192.168.50.1&p=8443&k=short&c=0MPM8E2H")]
    [InlineData("palisade://pair?h=192.168.50.1&p=8443&k=" + Pin)]
    [InlineData("")]
    [InlineData(null)]
    public void Anything_else_is_not_recognised(string? text) => Assert.Null(PairingLinks.Parse(text));

    [Theory]
    [InlineData("192.168.50.1", "192.168.50.1")]
    [InlineData("  http://192.168.50.1:8080/ ", "192.168.50.1")]
    [InlineData("https://palisade.lan", "palisade.lan")]
    [InlineData("[fe80::1]:8080", "fe80::1")]
    [InlineData("fe80::1", "fe80::1")]
    public void A_typed_address_finds_the_app_port_whatever_port_was_typed(string typed, string host) =>
        Assert.Equal(new FirewallAddress(host, PalisadeDefaults.ApiPort, null), PairingLinks.Typed(typed));

    [Theory]
    [InlineData("")]
    [InlineData("not an address")]
    [InlineData("http://")]
    public void A_typed_address_that_is_not_one_is_refused(string typed) => Assert.Null(PairingLinks.Typed(typed));

    [Fact]
    public void A_pin_is_shown_as_hex_pairs_and_odd_ones_are_refused()
    {
        Assert.Equal("8D:2F:A3:33", CertificatePin.Display(Pin, 4));
        Assert.True(CertificatePin.IsValid(Pin));
        Assert.False(CertificatePin.IsValid(Pin[..42]));
        Assert.False(CertificatePin.IsValid(Pin[..42] + "="));
        Assert.Equal("", CertificatePin.Display("!!!"));
    }
}
