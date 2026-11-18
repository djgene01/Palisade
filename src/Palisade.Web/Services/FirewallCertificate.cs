using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Palisade.Core;

namespace Palisade.Web.Services;

/// <summary>
/// The firewall's own certificate for the companion app's encrypted connection. No public authority can
/// vouch for a box on a home network, so it signs itself, and the app trusts it by remembering its key
/// when it is paired (the "pin"), never by asking the phone's list of authorities.
/// </summary>
public sealed class FirewallCertificate
{
    private const string FileName = "tls.pfx";

    public X509Certificate2 Certificate { get; }

    /// <summary>
    /// SHA-256 of the certificate's public key (its SubjectPublicKeyInfo), base64url without padding.
    /// Pinning the key rather than the whole certificate lets a renewed certificate on the same key keep working.
    /// </summary>
    public string Pin { get; }

    /// <summary>The pin as hex pairs, for comparing by eye: the first 16 bytes are enough for a person.</summary>
    public string ShortFingerprint => CertificatePin.Display(Pin, 16);

    public FirewallCertificate(string dataDirectory)
    {
        var path = Path.Combine(dataDirectory, FileName);
        if (!File.Exists(path)) Create(path);
        Certificate = X509CertificateLoader.LoadPkcs12FromFile(path, null);
        Pin = CertificatePin.Of(Certificate);
    }

    private static void Create(string path)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Palisade firewall", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("palisade");
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());

        // Long-lived on purpose: the app checks the pinned key, not the dates, and a new key means pairing every phone again.
        var now = DateTimeOffset.UtcNow;
        using var certificate = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(20));

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp";
        File.WriteAllBytes(temp, certificate.Export(X509ContentType.Pkcs12));
        // Holds the private key: only the web interface's own user may read it.
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.Move(temp, path, overwrite: true);
    }
}
