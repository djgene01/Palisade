using System.Globalization;

namespace Palisade.Core;

/// <summary>Strict IPv4 value. Parsing rejects anything that is not four plain decimal octets.</summary>
public readonly record struct Ip4(uint Value)
{
    public static bool TryParse(string? text, out Ip4 ip)
    {
        ip = default;
        if (string.IsNullOrEmpty(text)) return false;
        var parts = text.Split('.');
        if (parts.Length != 4) return false;
        uint value = 0;
        foreach (var part in parts)
        {
            if (part.Length is 0 or > 3 || !part.All(char.IsAsciiDigit)) return false;
            var octet = uint.Parse(part, CultureInfo.InvariantCulture);
            if (octet > 255) return false;
            value = (value << 8) | octet;
        }
        ip = new Ip4(value);
        return true;
    }

    public static uint Mask(int prefix) => prefix <= 0 ? 0 : uint.MaxValue << (32 - prefix);
    public static string MaskString(int prefix) => new Ip4(Mask(prefix)).ToString();

    public Ip4 Network(int prefix) => new(Value & Mask(prefix));
    public Ip4 Broadcast(int prefix) => new(Value | ~Mask(prefix));
    public bool IsIn(Ip4 network, int prefix) => (Value & Mask(prefix)) == (network.Value & Mask(prefix));

    public bool IsPrivate =>
        IsIn(new Ip4(0x0A000000), 8) || IsIn(new Ip4(0xAC100000), 12) || IsIn(new Ip4(0xC0A80000), 16);

    public override string ToString() =>
        $"{Value >> 24}.{(Value >> 16) & 255}.{(Value >> 8) & 255}.{Value & 255}";
}

public static class AddressSpec
{
    /// <summary>Accepts "10.0.0.5" or "10.0.0.0/24" and returns it in a canonical form safe to place in a ruleset.</summary>
    public static bool TryNormalize(string? text, out string normalized)
    {
        normalized = "";
        if (string.IsNullOrWhiteSpace(text)) return false;
        var parts = text.Trim().Split('/');
        if (parts.Length > 2 || !Ip4.TryParse(parts[0], out var ip)) return false;
        if (parts.Length == 1)
        {
            normalized = ip.ToString();
            return true;
        }
        if (parts[1].Length is 0 or > 2 || !parts[1].All(char.IsAsciiDigit)) return false;
        var prefix = int.Parse(parts[1], CultureInfo.InvariantCulture);
        if (prefix is < 1 or > 32) return false;
        normalized = prefix == 32 ? ip.ToString() : $"{ip.Network(prefix)}/{prefix}";
        return true;
    }

    /// <summary>Splits "192.168.1.20/24" style text as reported by the system.</summary>
    public static bool TryParseCidr(string? text, out Ip4 ip, out int prefix)
    {
        ip = default;
        prefix = 32;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var parts = text.Split('/');
        if (!Ip4.TryParse(parts[0], out ip)) return false;
        return parts.Length == 1 || int.TryParse(parts[1], out prefix) && prefix is >= 0 and <= 32;
    }
}

public readonly record struct PortRange(int From, int To)
{
    public override string ToString() => From == To ? From.ToString(CultureInfo.InvariantCulture) : $"{From}-{To}";
    public bool Overlaps(PortRange other) => From <= other.To && other.From <= To;
}

public static class PortSpec
{
    public static bool TryParseRange(string? text, out PortRange range)
    {
        range = default;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var parts = text.Trim().Split('-');
        if (parts.Length > 2 || !TryPort(parts[0], out var from)) return false;
        var to = from;
        if (parts.Length == 2 && !TryPort(parts[1], out to)) return false;
        if (to < from) return false;
        range = new PortRange(from, to);
        return true;
    }

    public static bool TryParseList(string? text, out List<PortRange> ranges)
    {
        ranges = [];
        if (string.IsNullOrWhiteSpace(text)) return false;
        foreach (var item in text.Split(',', StringSplitOptions.TrimEntries))
        {
            if (!TryParseRange(item, out var range)) return false;
            ranges.Add(range);
        }
        return ranges.Count > 0;
    }

    private static bool TryPort(string text, out int port)
    {
        port = 0;
        text = text.Trim();
        return text.Length is > 0 and <= 5 && text.All(char.IsAsciiDigit)
            && int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out port)
            && port is >= 1 and <= 65535;
    }
}
