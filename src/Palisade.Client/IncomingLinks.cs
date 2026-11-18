using Palisade.Core;

namespace Palisade.Client;

/// <summary>
/// What other apps hand the companion app: pairing links, shortcut links and shared text. This is where text
/// from outside the app enters it, so every rule about what is accepted lives here, in one tested place.
/// </summary>
public static class IncomingLinks
{
    /// <summary>The only pages a shortcut link may open.</summary>
    public static readonly IReadOnlySet<string> ShortcutPages = new HashSet<string>(StringComparer.Ordinal) { "/devices", "/filter" };

    /// <summary>
    /// The app page for a palisade:// link, or null for anything else. A pairing link goes to the Link page,
    /// which shows what it found and links only when the owner says so.
    /// </summary>
    public static string? PageFor(string? link)
    {
        if (!Uri.TryCreate(link, UriKind.Absolute, out var uri) || !uri.Scheme.Equals(AppContract.LinkScheme, StringComparison.OrdinalIgnoreCase)) return null;
        if (uri.Host.Equals("pair", StringComparison.OrdinalIgnoreCase))
            return PairingLinks.Parse(link) is null ? null : "/link?invite=" + Uri.EscapeDataString(link!);
        if (uri.Host.Equals("open", StringComparison.OrdinalIgnoreCase) && ShortcutPages.Contains(uri.AbsolutePath))
            return uri.AbsolutePath;
        return null;
    }

    /// <summary>The app page for text shared from another app, or null when there is nothing to share.</summary>
    public static string? PageForShared(string? text) =>
        string.IsNullOrWhiteSpace(text) ? null : "/share?text=" + Uri.EscapeDataString(text.Length > 2000 ? text[..2000] : text);

    /// <summary>
    /// The site a person most likely meant in shared text, such as "Look at this: https://www.example.org/x".
    /// A full web address wins over any other dotted word ("Node.js", "e.g."), then the first dotted word that
    /// is a site name. Null when there is none.
    /// </summary>
    public static string? FindSite(string? text)
    {
        var words = (text ?? "").Split((char[])[' ', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries)
            .Select(w => w.Trim('"', '\'', '(', ')', '<', '>', '[', ']', ',', ';'))
            .ToList();
        var addresses = words.Where(w => w.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || w.StartsWith("http://", StringComparison.OrdinalIgnoreCase));
        foreach (var word in addresses.Concat(words))
            if (SiteName.TryNormalize(word.TrimEnd('.'), out var site)) return site;
        return null;
    }
}
