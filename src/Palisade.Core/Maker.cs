namespace Palisade.Core;

/// <summary>
/// Working out who made a device from its hardware address. The first half of the address is a number
/// handed out to one manufacturer; the second half is the device's own and is never looked up.
/// </summary>
public static class Maker
{
    /// <summary>The manufacturer's half of the address, as six hex digits. Null when the address is not valid.</summary>
    public static string? Prefix(string mac) =>
        ConfigValidator.TryNormalizeMac(mac, out var normal) ? normal.Replace(":", "")[..6] : null;

    /// <summary>
    /// Phones and laptops often invent an address for each Wi-Fi network. Those are marked by one bit
    /// and belong to no manufacturer, so there is nothing to look up.
    /// </summary>
    public static bool IsMadeUp(string mac) =>
        Prefix(mac) is { } prefix && (Convert.ToInt32(prefix[..2], 16) & 0x02) != 0;

    /// <summary>Company names come from an outside service, so keep only a short line of plain text.</summary>
    public static string Clean(string? company)
    {
        var text = new string([.. (company ?? "").Where(ch => !char.IsControl(ch))]).Trim();
        return text.Length > 60 ? text[..60].Trim() : text;
    }
}
