using Palisade.Core;

namespace Palisade.Client.Tests;

/// <summary>What other apps can hand the companion app, and what it makes of it.</summary>
public sealed class IncomingLinkTests
{
    private const string Pin = "jS-jMyCvtjk3XVFHRkmtw8v4HspzydJsy7fSrovC7Ss";

    [Theory]
    [InlineData("Look at this: https://www.example.org/some/page?x=1", "example.org")]
    [InlineData("https://news.example.co.uk/article", "news.example.co.uk")]
    [InlineData("Using Node.js today https://www.example.org/x", "example.org")]
    [InlineData("e.g. see (https://tiktok.com/@someone).", "tiktok.com")]
    [InlineData("youtube.com", "youtube.com")]
    [InlineData("Check out example.org, it's great.", "example.org")]
    public void The_site_meant_is_found_with_a_full_address_winning(string shared, string site) =>
        Assert.Equal(site, IncomingLinks.FindSite(shared));

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("Just some words without any site")]
    [InlineData("http://192.168.1.10/admin")]
    public void Without_a_site_name_there_is_nothing_to_block(string? shared) => Assert.Null(IncomingLinks.FindSite(shared));

    [Fact]
    public void A_pairing_link_opens_the_link_page_with_it()
    {
        var link = AppContract.PairingLink("192.168.50.1", 8443, Pin, "PPYV6ZZQ");
        var page = IncomingLinks.PageFor(link);

        Assert.Equal("/link?invite=" + Uri.EscapeDataString(link), page);
    }

    [Theory]
    [InlineData("palisade://open/devices", "/devices")]
    [InlineData("palisade://open/filter", "/filter")]
    public void Shortcuts_open_their_page(string link, string page) => Assert.Equal(page, IncomingLinks.PageFor(link));

    [Theory]
    [InlineData("palisade://open/advanced")]
    [InlineData("palisade://open/firewalls")]
    [InlineData("palisade://open/../advanced")]
    [InlineData("palisade://pair?h=192.168.50.1")]
    [InlineData("palisade://elsewhere/devices")]
    [InlineData("https://evil.example/devices")]
    [InlineData("not a link")]
    [InlineData(null)]
    public void Anything_else_from_outside_opens_nothing(string? link) => Assert.Null(IncomingLinks.PageFor(link));

    [Fact]
    public void Shared_text_is_kept_short_and_empty_shares_are_ignored()
    {
        Assert.Null(IncomingLinks.PageForShared("   "));
        var page = IncomingLinks.PageForShared(new string('a', 5000));
        Assert.Equal(new string('a', 2000), Uri.UnescapeDataString(page!["/share?text=".Length..]));
    }
}
