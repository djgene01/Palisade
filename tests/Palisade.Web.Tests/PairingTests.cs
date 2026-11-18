using Palisade.Web.Services;

namespace Palisade.Web.Tests;

/// <summary>A clock the tests move by hand.</summary>
public sealed class ManualClock : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 11, 18, 12, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => Now;
}

public sealed class PairingTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "palisade-pairing-tests", Guid.NewGuid().ToString("N"));
    private readonly ManualClock _clock = new();

    public void Dispose()
    {
        try { Directory.Delete(_folder, recursive: true); } catch (IOException) { }
    }

    private PairedDevices Devices() => new(_folder, _clock);

    [Fact]
    public void A_code_is_eight_characters_people_can_read_aloud()
    {
        var code = Devices().NewCode().Code;
        Assert.Equal(8, code.Length);
        Assert.DoesNotContain(code, ch => "ILOU".Contains(ch) || char.IsLower(ch));
        Assert.Equal($"{code[..4]}-{code[4..]}", PairedDevices.Display(code));
    }

    [Fact]
    public void A_code_may_be_typed_with_its_dash_and_in_lower_case()
    {
        var devices = Devices();
        var code = devices.NewCode().Code;
        var (token, device, problem) = devices.Pair(PairedDevices.Display(code).ToLowerInvariant(), "  Kitchen tablet  ");

        Assert.NotNull(token);
        Assert.Equal("", problem);
        Assert.Equal("Kitchen tablet", device!.Name);
        Assert.Equal(device, devices.Verify(token));
    }

    [Fact]
    public void A_code_runs_out_after_five_minutes()
    {
        var devices = Devices();
        var code = devices.NewCode().Code;
        _clock.Now += PairedDevices.CodeLifetime;

        var (token, _, problem) = devices.Pair(code, "Late phone");
        Assert.Null(token);
        Assert.Contains("no pairing code waiting", problem);
        Assert.Null(devices.WaitingCode);
    }

    [Fact]
    public void Five_wrong_guesses_throw_the_code_away()
    {
        var devices = Devices();
        var code = devices.NewCode().Code;
        for (var i = 0; i < 4; i++)
            Assert.Contains("not the one", devices.Pair("WRONG000", "Guesser").Problem);

        Assert.Contains("too many times", devices.Pair("WRONG000", "Guesser").Problem);
        // Even the right code is refused now: the owner has to make a new one.
        Assert.Null(devices.Pair(code, "Owner").Token);
    }

    [Fact]
    public void A_new_code_replaces_the_one_before()
    {
        var devices = Devices();
        var old = devices.NewCode().Code;
        var current = devices.NewCode().Code;

        Assert.Null(devices.Pair(old, "Phone").Token);
        Assert.NotNull(devices.Pair(current, "Phone").Token);
    }

    [Fact]
    public void Linked_devices_survive_a_restart_and_a_removal_lasts()
    {
        var first = Devices();
        var token = first.Pair(first.NewCode().Code, "Phone").Token;
        var other = first.Pair(first.NewCode().Code, "Tablet").Token;

        var restarted = Devices();
        Assert.Equal(["Phone", "Tablet"], restarted.Devices.Select(d => d.Name));
        Assert.NotNull(restarted.Verify(token));

        restarted.Remove(restarted.Devices.Single(d => d.Name == "Phone").Id);
        var again = Devices();
        Assert.Null(again.Verify(token));
        Assert.NotNull(again.Verify(other));
    }

    [Fact]
    public void Names_are_cleaned_and_kept_short()
    {
        var devices = Devices();
        Assert.Equal("Phone", devices.Pair(devices.NewCode().Code, " \t ").Device!.Name);
        var longName = devices.Pair(devices.NewCode().Code, new string('x', 100) + "\n").Device!.Name;
        Assert.Equal(PairedDevices.MaxNameLength, longName.Length);
    }

    [Fact]
    public void Last_seen_is_noted_without_writing_on_every_request()
    {
        var devices = Devices();
        var token = devices.Pair(devices.NewCode().Code, "Phone").Token;
        var file = Path.Combine(_folder, "devices.json");
        var written = File.GetLastWriteTimeUtc(file);

        _clock.Now += TimeSpan.FromMinutes(5);
        devices.Verify(token);
        Assert.Equal(written, File.GetLastWriteTimeUtc(file));

        _clock.Now += TimeSpan.FromMinutes(6);
        Assert.Equal(_clock.Now, devices.Verify(token)!.LastSeen);
    }

    [Fact]
    public void The_certificate_key_and_its_pin_stay_the_same_across_restarts()
    {
        var first = new FirewallCertificate(_folder);
        var second = new FirewallCertificate(_folder);

        Assert.Equal(first.Pin, second.Pin);
        Assert.Equal(43, first.Pin.Length);
        Assert.Equal(16, first.ShortFingerprint.Split(':').Length);

        File.Delete(Path.Combine(_folder, "tls.pfx"));
        Assert.NotEqual(first.Pin, new FirewallCertificate(_folder).Pin);
    }
}
