using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Palisade.Core;

/// <summary>
/// What the firewall's app interface and the companion app agree on. Both sides use these very types, so
/// a change here is a change to the interface: raise <see cref="Version"/> when older apps could not follow it.
/// </summary>
public static class AppContract
{
    public const int Version = 1;
    public const string Prefix = "/api/v1";
    /// <summary>The link a pairing QR code holds: palisade://pair?h=host&amp;p=port&amp;k=pin&amp;c=code.</summary>
    public const string LinkScheme = "palisade";

    /// <summary>
    /// Hardware addresses asked about in one request. Each takes about 32 bytes in the address line, and the
    /// web server refuses lines over 8 KB, so this leaves plenty of room.
    /// </summary>
    public const int MakersPerRequest = 100;

    /// <summary>Everything the app needs in one link: where to go, which key to expect there, and the one-time code.</summary>
    public static string PairingLink(string host, int port, string pin, string code) =>
        $"{LinkScheme}://pair?h={Uri.EscapeDataString(host)}&p={port.ToString(System.Globalization.CultureInfo.InvariantCulture)}&k={pin}&c={Uri.EscapeDataString(code)}";
}

/// <summary>What the firewall says about itself before pairing: enough for the app to know it found the right thing.</summary>
public sealed record ApiInfo(string Product, int Api, string Version);

public sealed record PairRequest(string? Code, string? Name);

public sealed record PairResponse(string DeviceId, string Token)
{
    /// <summary>Leaves the token out, so it never lands in a log by accident.</summary>
    public override string ToString() => $"PairResponse {{ DeviceId = {DeviceId} }}";
}

/// <summary>A problem in plain words, the same kind the web pages show.</summary>
public sealed record ApiProblem(string Problem);

/// <summary>
/// The fingerprint by which the app recognises its firewall: SHA-256 of the certificate's public key
/// (the whole SubjectPublicKeyInfo, not just the raw key point), base64url without padding.
/// Keeping the key rather than the whole certificate lets a renewed certificate on the same key keep working.
/// </summary>
public static class CertificatePin
{
    public static string Of(X509Certificate2 certificate) =>
        Convert.ToBase64String(SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>The first bytes of a pin as hex pairs ("8D:2F:A3:…"), for comparing by eye. Empty for a malformed pin.</summary>
    public static string Display(string pin, int bytes = 8)
    {
        var s = pin.Replace('-', '+').Replace('_', '/');
        s += new string('=', (4 - s.Length % 4) % 4);
        try { return string.Join(':', Convert.FromBase64String(s).Take(bytes).Select(b => b.ToString("X2"))); }
        catch (FormatException) { return ""; }
    }

    /// <summary>True for something shaped like a pin: 32 bytes in base64url.</summary>
    public static bool IsValid(string? pin) =>
        pin is { Length: 43 } && pin.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_');
}
