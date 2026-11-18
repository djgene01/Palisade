using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Palisade.Core;

namespace Palisade.Client;

/// <summary>A problem reaching or using a firewall, already in the plain words the app shows.</summary>
public class FirewallException(string message, Exception? inner = null) : PlainWordsException(message, inner);

/// <summary>The firewall no longer knows this device: its link was removed there, or the firewall was reset.</summary>
public sealed class LinkRemovedException(string message) : FirewallException(message);

/// <summary>
/// HTTPS to a firewall that signs its own certificate. No authority vouches for it, so the usual checks
/// (who issued it, which name it is for) cannot pass. Instead the connection goes ahead only when the
/// certificate carries the one key this app was told to expect, which is a stricter test than the usual one.
/// </summary>
public static class PinnedConnection
{
    public static readonly JsonSerializerOptions Json = PalisadeJson.Options;

    /// <summary>A handler that accepts the firewall only with the expected key. Every new connection is checked.</summary>
    public static SocketsHttpHandler Handler(string pin, bool freshConnections = false) => new()
    {
        SslOptions = new SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                certificate is not null && CertificatePin.Of(AsCertificate2(certificate)) == pin,
        },
        // A probe must open a brand-new connection each time, or it proves nothing about the rules.
        PooledConnectionLifetime = freshConnections ? TimeSpan.Zero : TimeSpan.FromMinutes(2),
        ConnectTimeout = TimeSpan.FromSeconds(8),
    };

    public static HttpClient Client(FirewallAddress address, string pin, string? token = null)
    {
        var http = new HttpClient(Handler(pin), disposeHandler: true) { BaseAddress = address.BaseUri, Timeout = Timeout.InfiniteTimeSpan };
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (token is not null) http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return http;
    }

    /// <summary>
    /// Asks a firewall who it is, and reads which key it presented while doing so. Used before linking: with a
    /// scanned code the key must match the one in the code; with a typed address the person compares it by eye.
    /// </summary>
    public static async Task<(ApiInfo Info, string Pin)> IntroduceAsync(FirewallAddress address, CancellationToken ct = default)
    {
        string? seen = null;
        using var handler = new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                // Nothing is sent but this one request for public facts, so any key is accepted here and recorded.
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                {
                    if (certificate is not null) seen = CertificatePin.Of(AsCertificate2(certificate));
                    return certificate is not null;
                },
            },
            ConnectTimeout = TimeSpan.FromSeconds(8),
        };
        using var http = new HttpClient(handler) { BaseAddress = address.BaseUri, Timeout = TimeSpan.FromSeconds(15) };
        ApiInfo? info;
        try
        {
            info = await http.GetFromJsonAsync<ApiInfo>($"{AppContract.Prefix}/info", Json, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            throw new FirewallException($"No Palisade firewall answered at {address.Host}. Check the address, and that this device is on your home network.", ex);
        }
        if (seen is null) throw new FirewallException($"Something answered at {address.Host}, but it is not a Palisade firewall.");
        CheckCompatible(info, address.Host);
        return (info!, seen);
    }

    /// <summary>Refuses anything that is not a Palisade firewall speaking this app's version of the interface.</summary>
    public static void CheckCompatible(ApiInfo? info, string host = "that address")
    {
        if (info is null || info.Product != "Palisade")
            throw new FirewallException($"Something answered at {host}, but it is not a Palisade firewall.");
        if (info.Api != AppContract.Version)
            throw new FirewallException(info.Api > AppContract.Version
                ? "This firewall is newer than this app. Update the app, then link again."
                : "This firewall needs updating before this app can use it. Update it from its Advanced page.");
    }

    /// <summary>Turns a failed call into the message to show, keeping the firewall's own explanation when it gave one.</summary>
    public static async Task EnsureOkAsync(HttpResponseMessage response, CancellationToken ct)
    {
        if (response.IsSuccessStatusCode) return;
        var problem = await ProblemAsync(response, ct);
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            throw new LinkRemovedException(problem ?? "This device is no longer linked to the firewall. Link it again from the firewall's Advanced page.");
        throw new FirewallException(problem ?? $"The firewall could not do that ({(int)response.StatusCode} {response.ReasonPhrase}).");
    }

    private static async Task<string?> ProblemAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try { return (await response.Content.ReadFromJsonAsync<ApiProblem>(Json, ct))?.Problem; }
        catch (Exception ex) when (ex is JsonException or NotSupportedException or InvalidOperationException) { return null; }
    }

    private static X509Certificate2 AsCertificate2(X509Certificate certificate) =>
        certificate as X509Certificate2 ?? X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
}
