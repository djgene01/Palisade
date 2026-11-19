using System.Text.Json;
using Palisade.Core;

namespace Palisade.Core.Tests;

public class HealthTests
{
    // Captured from Debian 13 (trixie).
    private const string ProcStat = "cpu  506 0 1009 26144 286 0 165 0 0 0\ncpu0 15 0 72 754 12 0 104 0 0 0\ncpu1 8 0 22 837 8 0 17 0 0 0\n";
    private const string MemInfo = """
        MemTotal:       14122728 kB
        MemFree:        12017328 kB
        MemAvailable:   13031620 kB
        Buffers:           47320 kB
        Cached:          1154456 kB
        SwapCached:            0 kB
        """;

    private static readonly DateTimeOffset Noon = new(2026, 11, 19, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Processor_time_counts_waiting_for_the_disk_as_idle()
    {
        var (busy, total) = HealthParse.CpuTimes(ProcStat)!.Value;
        Assert.Equal(506 + 1009 + 165, busy);
        Assert.Equal(506 + 1009 + 26144 + 286 + 165, total);
    }

    [Fact]
    public void Processor_use_is_the_growth_between_two_readings_and_nothing_when_counters_went_back()
    {
        Assert.Equal(25, HealthParse.CpuPercent((100, 1000), (150, 1200)));
        Assert.Null(HealthParse.CpuPercent((100, 1000), (100, 1000)));
        Assert.Null(HealthParse.CpuPercent((500, 9000), (100, 1000)));
        Assert.Null(HealthParse.CpuTimes("nonsense"));
    }

    [Fact]
    public void Memory_in_use_is_what_linux_could_not_hand_out_at_once()
    {
        var (used, total) = HealthParse.Memory(MemInfo)!.Value;
        Assert.Equal(14122728L * 1024, total);
        Assert.Equal((14122728L - 13031620) * 1024, used);
        // An old kernel without MemAvailable: free plus what it can drop.
        var (oldUsed, _) = HealthParse.Memory("MemTotal: 1000 kB\nMemFree: 200 kB\nBuffers: 100 kB\nCached: 300 kB\n")!.Value;
        Assert.Equal(400 * 1024, oldUsed);
        Assert.Null(HealthParse.Memory(""));
    }

    [Fact]
    public void Disk_use_matches_what_df_shows()
    {
        // df on the same machine: used 107710312448, available 918398509056, Use% 11.
        Assert.Equal(11, Math.Ceiling(HealthParse.DiskPercent(107710312448, 918398509056)));
        Assert.Equal(0.42, HealthParse.Load("0.42 0.30 0.21 1/180 4242\n"));
    }

    [Fact]
    public void Readings_are_averaged_into_minutes_with_the_busiest_kept()
    {
        var history = new HealthHistory();
        history.Record(Noon, null, 40, 20);
        history.Record(Noon.AddSeconds(10), 10, 42, 20);
        history.Record(Noon.AddSeconds(20), 90, 44, 21);
        var point = Assert.Single(history.Report(HealthRange.Hour, Noon.AddSeconds(30)).Points);
        Assert.Equal(Noon.ToUnixTimeSeconds(), point.At);
        Assert.Equal(50, point.Cpu);
        Assert.Equal(90, point.CpuPeak);
        Assert.Equal(42, point.Memory);
        Assert.Equal(21, point.Disk);
    }

    [Fact]
    public void Each_range_is_a_few_hundred_points_at_most_and_a_gap_is_left_out()
    {
        var history = new HealthHistory();
        var start = Noon - TimeSpan.FromDays(31);
        for (var at = start; at <= Noon; at += TimeSpan.FromSeconds(30))
        {
            // The firewall was off for two hours yesterday.
            if (at > Noon.AddDays(-1).AddHours(-2) && at < Noon.AddDays(-1)) continue;
            history.Record(at, 10, 30, 50);
        }
        foreach (var range in Enum.GetValues<HealthRange>())
        {
            var report = history.Report(range, Noon);
            Assert.InRange(report.Points.Count, 2, 300);
            Assert.All(report.Points, p => Assert.Equal(0, p.At % report.Step));
            Assert.True(report.Points.SequenceEqual(report.Points.OrderBy(p => p.At)));
        }
        var week = history.Report(HealthRange.Week, Noon).Points;
        Assert.Contains(week.Zip(week.Skip(1)), pair => pair.Second.At - pair.First.At >= 2 * 3600);
        // Minutes are only kept for a day, so the hour view needs no more than that.
        Assert.InRange(history.Report(HealthRange.Hour, Noon).Points.Count, 60, 61);
    }

    [Fact]
    public void Old_readings_are_forgotten_and_a_clock_set_back_drops_what_now_lies_ahead()
    {
        var history = new HealthHistory();
        history.Record(Noon - TimeSpan.FromDays(40), 10, 10, 10);
        history.Record(Noon, 20, 20, 20);
        Assert.DoesNotContain(history.Export(), b => b.At < (Noon - TimeSpan.FromDays(32)).ToUnixTimeSeconds());

        // A box without a battery clock boots in the past, then learns the right time.
        var past = Noon - TimeSpan.FromDays(2);
        history.Record(past, 30, 30, 30);
        Assert.DoesNotContain(history.Export(), b => b.At > past.ToUnixTimeSeconds());
    }

    [Fact]
    public void History_survives_a_save_and_a_bad_file_is_not_trusted()
    {
        var history = new HealthHistory();
        for (var i = 0; i < 30; i++) history.Record(Noon.AddMinutes(i), i, 40, 50);
        var json = JsonSerializer.Serialize(history.Export(), PalisadeJson.Options);

        var loaded = new HealthHistory();
        loaded.Import(JsonSerializer.Deserialize<List<HealthBucket>>(json, PalisadeJson.Options), Noon.AddMinutes(30));
        Assert.Equal(history.Report(HealthRange.Day, Noon.AddMinutes(30)).Points, loaded.Report(HealthRange.Day, Noon.AddMinutes(30)).Points);

        var bad = new HealthHistory();
        bad.Import([
            new HealthBucket(60, Noon.ToUnixTimeSeconds() + 7, 1, 1, 10, 10, 10, 10),     // not on a minute
            new HealthBucket(60, Noon.ToUnixTimeSeconds(), 1, 1, 500, 10, 10, 10),       // more than 100%
            new HealthBucket(60, Noon.ToUnixTimeSeconds(), 1, 2, 10, 10, 10, 10),        // more processor readings than readings
            new HealthBucket(42, Noon.ToUnixTimeSeconds(), 1, 1, 10, 10, 10, 10),        // no such size
            new HealthBucket(60, Noon.AddDays(5).ToUnixTimeSeconds(), 1, 1, 10, 10, 10, 10), // in the future
        ], Noon);
        Assert.Empty(bad.Export());
        new HealthHistory().Import(null, Noon);
    }

    [Fact]
    public async Task The_demo_has_a_month_of_history_with_a_restart_in_it()
    {
        var report = await new SimulatedHealth().GetHealthAsync(HealthRange.Month);
        Assert.NotNull(report.Now?.CpuPercent);
        Assert.InRange(report.Points.Count, 200, 300);
        var week = (await new SimulatedHealth().GetHealthAsync(HealthRange.Week)).Points;
        Assert.InRange(week.Count, 150, 170);
    }
}
