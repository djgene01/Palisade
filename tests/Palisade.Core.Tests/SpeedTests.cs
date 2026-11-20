using Palisade.Core;

namespace Palisade.Core.Tests;

public class SpeedTests
{
    // Captured from Speedtest by Ookla 1.2.0 on Debian 13. The licence banner goes to the error stream, which is read too.
    private const string Real = """
        ==============================================================================

        You may only use this Speedtest software and information generated
        from it for personal, non-commercial use, through a command line
        interface on a personal computer.
        ==============================================================================

        License acceptance recorded. Continuing.

        {"type":"result","timestamp":"2026-11-20T04:07:11Z","ping":{"jitter":4.228,"latency":20.891,"low":4.484,"high":21.175},"download":{"bandwidth":5392708,"bytes":37805120,"elapsed":6709,"latency":{"iqm":11.073,"low":3.927,"high":63.746,"jitter":13.960}},"upload":{"bandwidth":10468615,"bytes":67674353,"elapsed":6510,"latency":{"iqm":22.813,"low":11.089,"high":85.660,"jitter":4.949}},"packetLoss":0,"isp":"airmobile.co.za","interface":{"internalIp":"172.17.0.3","name":"eth0","macAddr":"8A:05:A4:27:AD:3D","isVpn":false,"externalIp":"102.182.43.147"},"server":{"id":15532,"host":"speedtestupload.activefibre.co.za","port":8080,"name":"Active Fibre","location":"Johannesburg","country":"South Africa","ip":"196.61.224.151"},"result":{"id":"02bbb76b-5be3-4008-9b5f-6cbeddf7b7aa","url":"https://www.speedtest.net/result/c/02bbb76b-5be3-4008-9b5f-6cbeddf7b7aa","persisted":true}}
        """;

    private static readonly DateTimeOffset At = new(2026, 11, 20, 4, 7, 0, TimeSpan.Zero);

    [Fact]
    public void A_real_result_is_read_in_bits_per_second_and_keeps_nothing_that_identifies_the_line()
    {
        var r = SpeedPlan.Parse(Real, At, SpeedPlan.Manual);
        Assert.Empty(r.Problem);
        Assert.Equal(5392708 * 8.0, r.DownloadBps);
        Assert.Equal(10468615 * 8.0, r.UploadBps);
        Assert.Equal(20.891, r.PingMs);
        Assert.Equal(4.228, r.JitterMs);
        Assert.Equal(0, r.PacketLoss);
        Assert.Equal("Active Fibre, Johannesburg", r.Server);
        Assert.Equal("airmobile.co.za", r.Isp);
        Assert.Equal(37805120 + 67674353, r.DataBytes);
        Assert.Equal("https://www.speedtest.net/result/c/02bbb76b-5be3-4008-9b5f-6cbeddf7b7aa", r.ResultUrl);
        Assert.Equal("43.1 Mbit/s", SpeedPlan.Format(r.DownloadBps));
        // Ookla also reports the public address and hardware details; none of it is kept.
        var saved = System.Text.Json.JsonSerializer.Serialize(r, PalisadeJson.Options);
        Assert.DoesNotContain("102.182.43.147", saved);
        Assert.DoesNotContain("8A:05", saved);
    }

    [Fact]
    public void An_error_ookla_logs_becomes_a_plain_problem()
    {
        var r = SpeedPlan.Parse("""{"type":"log","timestamp":"2026-11-20T04:07:11Z","message":"Configuration - No servers defined (NoServersException)","level":"error"}""", At, SpeedPlan.Scheduled);
        Assert.Equal("The speed test failed: Configuration - No servers defined (NoServersException)", r.Problem);
        Assert.Equal(0, r.DownloadBps);
        Assert.Equal("The speed test gave no result.", SpeedPlan.Parse("Segmentation fault", At, SpeedPlan.Scheduled).Problem);
        // A link anywhere but speedtest.net is never shown.
        Assert.Empty(SpeedPlan.Parse(Real.Replace("https://www.speedtest.net/result/", "https://evil.example/"), At, SpeedPlan.Manual).ResultUrl);
    }

    [Fact]
    public void A_household_using_the_internet_puts_a_scheduled_test_off()
    {
        static UsageReport Using(double bytesPerSecond) => new() { Devices = [new DeviceUsage("192.168.50.100", 0, 0, bytesPerSecond, 0)] };
        var last = new SpeedResult { DownloadBps = 100e6 };
        Assert.False(SpeedPlan.IsBusy(Using(1e6), last));          // 8 Mbit/s of 100: quiet
        Assert.True(SpeedPlan.IsBusy(Using(3e6), last));           // 24 Mbit/s of 100: busy
        Assert.True(SpeedPlan.IsBusy(Using(1e6), null));           // 8 Mbit/s before any test: over 5
        Assert.False(SpeedPlan.IsBusy(Using(0.5e6), new SpeedResult { DownloadBps = 10e6 }));   // a slow line never needs less than 5 Mbit/s
    }

    [Fact]
    public void Tests_need_ookla_terms_once_and_a_known_interval()
    {
        var none = new SpeedSettings();
        Assert.NotNull(SpeedPlan.Validate(new SpeedSettingsRequest { Enabled = true }, none));
        Assert.Null(SpeedPlan.Validate(new SpeedSettingsRequest { Enabled = true, AcceptTerms = true }, none));
        Assert.Null(SpeedPlan.Validate(new SpeedSettingsRequest { Enabled = true }, new SpeedSettings { TermsAcceptedAt = At }));
        Assert.NotNull(SpeedPlan.Validate(new SpeedSettingsRequest { Enabled = true, IntervalMinutes = 5, AcceptTerms = true }, none));
        Assert.Null(SpeedPlan.Validate(new SpeedSettingsRequest { Enabled = false }, none));
    }

    [Fact]
    public void Only_the_newest_results_keep_their_words_when_sent_to_a_page()
    {
        var full = Enumerable.Range(0, 50).Select(i => SpeedPlan.Parse(Real, At.AddMinutes(-30 * i), SpeedPlan.Scheduled)).ToList();
        var sent = SpeedPlan.ForWire(full);
        Assert.Equal(50, sent.Count);
        Assert.All(sent.Take(SpeedPlan.DetailedResults), r => Assert.NotEmpty(r.Server));
        Assert.All(sent.Skip(SpeedPlan.DetailedResults), r => Assert.Empty(r.Server + r.Isp + r.ResultUrl));
        Assert.Equal(full[^1].DownloadBps, sent[^1].DownloadBps, 0.5);
    }

    [Fact]
    public async Task The_demo_has_a_month_of_tests_and_a_test_by_hand_finishes()
    {
        var demo = new SimulatedSpeedTest();
        var status = await demo.GetSpeedAsync();
        Assert.True(status.Settings.Enabled);
        Assert.InRange(status.History.Count, 1200, 1490);
        Assert.True((await demo.RunSpeedTestAsync()).Running);
    }
}
