using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Palisade.Core;
using Palisade.Web.Services;

namespace Palisade.Web.Tests;

/// <summary>
/// Starts the whole web interface in memory, on the simulated network, with its own empty data folder.
/// The settings travel as environment variables because the web interface reads them before it is built.
/// </summary>
public sealed class WebInterface : WebApplicationFactory<Program>
{
    public string DataDirectory { get; } = Path.Combine(Path.GetTempPath(), "palisade-web-tests", Guid.NewGuid().ToString("N"));

    public WebInterface()
    {
        Environment.SetEnvironmentVariable("STATE_DIRECTORY", DataDirectory);
        Environment.SetEnvironmentVariable("Palisade__Backend", "simulated");
        Environment.SetEnvironmentVariable("Palisade__MakerLookup", "false");
    }

    public PairedDevices Paired => Services.GetRequiredService<PairedDevices>();

    /// <summary>A client on the encrypted port, which is where the app's interface lives.</summary>
    public HttpClient Https(string? token = null)
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        if (token is not null) client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    /// <summary>A client on plain HTTP, like a browser on the web pages.</summary>
    public HttpClient Http() =>
        CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("http://localhost"), AllowAutoRedirect = false });

    public async Task<string> PairAsync(string name = "Test phone")
    {
        var code = Paired.NewCode();
        var response = await Https().PostAsJsonAsync("/api/v1/pair", new { code = code.Code, name });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<PairResponse>(Json))!.Token;
    }

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { Directory.Delete(DataDirectory, recursive: true); } catch (IOException) { }
    }
}

// Every test class starts its own web interface through process-wide environment variables, so they take turns.
[CollectionDefinition("web", DisableParallelization = true)]
public sealed class WebCollection;

[Collection("web")]
public sealed class AppApiTests : IDisposable
{
    private readonly WebInterface _web = new();

    public void Dispose() => _web.Dispose();

    [Theory]
    [InlineData("/api/v1/info")]
    [InlineData("/api/v1/status")]
    public async Task The_app_interface_is_never_served_over_plain_http(string path)
    {
        var response = await _web.Http().GetAsync(path);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/login")]
    [InlineData("/api/whoami")]
    public async Task The_encrypted_port_serves_nothing_but_the_app_interface(string path)
    {
        var response = await _web.Https().GetAsync(path);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Theory]
    [InlineData("/")]
    // Raw packets from devices waiting for approval: never without the password.
    [InlineData("/zero-trust/capture")]
    public async Task The_web_pages_still_ask_for_the_password(string path)
    {
        var response = await _web.Http().GetAsync(path);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/setup", response.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task The_app_can_switch_zero_trust_and_change_approvals_only_with_its_token()
    {
        var anonymous = _web.Https();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync("/api/v1/zerotrust", new ZeroTrustRequest(), WebInterface.Json)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync("/api/v1/approvals", new ApprovalChange { Mac = "52:54:00:bb:00:66" }, WebInterface.Json)).StatusCode);
    }

    [Fact]
    public async Task Info_and_ping_answer_before_pairing()
    {
        var info = await _web.Https().GetFromJsonAsync<ApiInfo>("/api/v1/info", WebInterface.Json);
        Assert.Equal(new ApiInfo("Palisade", AppApi.Version, "dev"), info);

        var ping = await _web.Https().GetAsync("/api/v1/ping");
        Assert.Equal(HttpStatusCode.NoContent, ping.StatusCode);
        Assert.Contains("no-store", ping.Headers.CacheControl!.ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not-a-real-token")]
    public async Task Everything_else_needs_a_linked_device(string? token)
    {
        var response = await _web.Https(token).GetAsync("/api/v1/status");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Bearer", response.Headers.WwwAuthenticate.Single().Scheme);
        // The cookie that opens the web pages does not open the app interface.
        Assert.Contains("not linked", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A_linked_device_reads_the_same_firewall_as_the_web_pages()
    {
        var token = await _web.PairAsync();
        var client = _web.Https(token);

        var status = await client.GetFromJsonAsync<SystemStatus>("/api/v1/status", WebInterface.Json);
        Assert.True(status!.Simulated);
        var config = await client.GetFromJsonAsync<FirewallConfig>("/api/v1/config", WebInterface.Json);
        Assert.False(config!.SetupComplete);
        // Before setup nothing hands out addresses yet, so the list is empty, but the call works.
        Assert.NotNull(await client.GetFromJsonAsync<List<DhcpLease>>("/api/v1/leases", WebInterface.Json));
        Assert.NotNull(await client.GetFromJsonAsync<UsageReport>("/api/v1/usage", WebInterface.Json));
        Assert.NotNull(await client.GetFromJsonAsync<WifiStatus>("/api/v1/wifi", WebInterface.Json));
        Assert.NotNull(await client.GetFromJsonAsync<UpdateStatus>("/api/v1/update", WebInterface.Json));
        var makers = await client.GetFromJsonAsync<Dictionary<string, string?>>("/api/v1/makers?mac=52:54:00:00:00:01&mac=52:54:00:00:00:02", WebInterface.Json);
        Assert.Equal(["52:54:00:00:00:01", "52:54:00:00:00:02"], makers!.Keys.Order());
    }

    [Fact]
    public async Task A_change_from_the_app_waits_for_confirmation_like_one_from_the_web_pages()
    {
        var client = _web.Https(await _web.PairAsync());
        var status = await client.GetFromJsonAsync<SystemStatus>("/api/v1/status", WebInterface.Json);
        var config = await client.GetFromJsonAsync<FirewallConfig>("/api/v1/config", WebInterface.Json);
        config!.WanInterface = status!.Interfaces[0].Name;
        config.LanInterface = status.Interfaces[1].Name;
        config.SetupComplete = true;

        var applied = await (await client.PostAsJsonAsync("/api/v1/config/apply", config, WebInterface.Json)).Content.ReadFromJsonAsync<ApplyResult>(WebInterface.Json);
        Assert.True(applied!.Ok, string.Join("; ", applied.Issues.Select(i => i.Message)));
        Assert.Equal(PalisadeDefaults.ConfirmSeconds, applied.ConfirmWithinSeconds);
        Assert.NotNull((await client.GetFromJsonAsync<SystemStatus>("/api/v1/status", WebInterface.Json))!.PendingSecondsLeft);

        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/api/v1/config/confirm", null)).StatusCode);
        Assert.Null((await client.GetFromJsonAsync<SystemStatus>("/api/v1/status", WebInterface.Json))!.PendingSecondsLeft);
        Assert.True((await client.GetFromJsonAsync<FirewallConfig>("/api/v1/config", WebInterface.Json))!.SetupComplete);
    }

    [Fact]
    public async Task A_rejected_change_comes_back_with_the_reasons()
    {
        var client = _web.Https(await _web.PairAsync());
        var config = await client.GetFromJsonAsync<FirewallConfig>("/api/v1/config", WebInterface.Json);
        config!.LanAddress = "not an address";

        var result = await (await client.PostAsJsonAsync("/api/v1/config/apply", config, WebInterface.Json)).Content.ReadFromJsonAsync<ApplyResult>(WebInterface.Json);
        Assert.False(result!.Ok);
        Assert.NotEmpty(result.Issues);
    }

    [Fact]
    public async Task A_removed_device_is_shut_out_at_once()
    {
        var token = await _web.PairAsync("Lost phone");
        Assert.Equal(HttpStatusCode.OK, (await _web.Https(token).GetAsync("/api/v1/status")).StatusCode);

        _web.Paired.Remove(_web.Paired.Devices.Single(d => d.Name == "Lost phone").Id);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _web.Https(token).GetAsync("/api/v1/status")).StatusCode);
    }

    [Fact]
    public async Task A_device_can_unlink_itself()
    {
        var token = await _web.PairAsync("Old tablet");
        Assert.Equal(HttpStatusCode.NoContent, (await _web.Https(token).PostAsync("/api/v1/unpair", null)).StatusCode);
        Assert.DoesNotContain(_web.Paired.Devices, d => d.Name == "Old tablet");
        Assert.Equal(HttpStatusCode.Unauthorized, (await _web.Https(token).GetAsync("/api/v1/status")).StatusCode);
    }

    [Fact]
    public async Task A_pairing_code_works_once()
    {
        var code = _web.Paired.NewCode();
        var first = await _web.Https().PostAsJsonAsync("/api/v1/pair", new { code = code.Code, name = "First" });
        var second = await _web.Https().PostAsJsonAsync("/api/v1/pair", new { code = code.Code, name = "Second" });

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, second.StatusCode);
        Assert.Contains("no pairing code waiting", (await second.Content.ReadFromJsonAsync<ApiProblem>(WebInterface.Json))!.Problem);
    }

    [Fact]
    public async Task The_token_is_never_stored()
    {
        var token = await _web.PairAsync();
        var saved = await File.ReadAllTextAsync(Path.Combine(_web.DataDirectory, "devices.json"));
        Assert.DoesNotContain(token, saved);
        Assert.Contains("Test phone", saved);
    }
}
