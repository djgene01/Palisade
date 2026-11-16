using System.Text.RegularExpressions;

namespace Palisade.Core;

public enum DeviceType { Unknown, Phone, Computer, Tv, Camera, SmartHome, Console, Printer, Server, Speaker, Network }

/// <summary>
/// A best guess at what kind of thing a device is, from what it calls itself and who made it.
/// Only ever used to pick a picture: a wrong guess changes nothing about how the device is treated.
/// </summary>
public static partial class DeviceKind
{
    [GeneratedRegex("[^a-z0-9]+")]
    private static partial Regex NotWord();

    // Whole words in the device's own name. A name says more than a maker does, so it is tried first.
    private static readonly (DeviceType Type, string[] Words)[] NameWords =
    [
        (DeviceType.Phone, ["iphone", "ipad", "phone", "android", "galaxy", "pixel", "tablet", "tab", "oneplus", "redmi"]),
        (DeviceType.Console, ["playstation", "ps4", "ps5", "xbox", "nintendo", "steamdeck"]),
        (DeviceType.Camera, ["cam", "camera", "ipcam", "doorbell", "nvr", "dvr"]),
        (DeviceType.Tv, ["tv", "roku", "chromecast", "firetv", "firestick", "appletv", "bravia", "webos"]),
        (DeviceType.Printer, ["printer", "print", "laserjet", "officejet", "deskjet", "epson", "brother"]),
        (DeviceType.Server, ["server", "nas", "proxmox", "pve", "esxi", "synology", "truenas", "unraid", "docker"]),
        (DeviceType.Speaker, ["echo", "sonos", "homepod", "speaker", "alexa", "nest"]),
        (DeviceType.Network, ["router", "ap", "switch", "unifi", "mikrotik", "extender", "repeater", "mesh"]),
        (DeviceType.SmartHome, ["light", "lamp", "bulb", "plug", "socket", "sensor", "thermostat", "tuya", "shelly", "sonoff", "tasmota", "esp", "wled"]),
        (DeviceType.Computer, ["laptop", "desktop", "pc", "macbook", "imac", "thinkpad", "surface", "notebook", "workstation"]),
    ];

    // Parts of company names. Makers that sell several kinds of thing (Apple, Samsung, Amazon, Google) are
    // left out on purpose: a neutral picture is better than a confident wrong one.
    private static readonly (DeviceType Type, string[] Parts)[] MakerParts =
    [
        (DeviceType.Camera, ["hikvision", "dahua", "reolink", "axis communications", "amcrest", "arlo", "wyze", "ezviz", "foscam"]),
        (DeviceType.SmartHome, ["tuya", "espressif", "shelly", "allterco", "itead", "sonoff", "signify", "philips lighting", "high-flying", "yeelight", "lifx", "meross", "broadlink", "ikea"]),
        (DeviceType.Console, ["nintendo", "sony interactive", "valve"]),
        (DeviceType.Server, ["proxmox", "synology", "qnap", "super micro", "supermicro", "vmware"]),
        (DeviceType.Printer, ["brother industries", "canon", "seiko epson", "kyocera", "lexmark", "xerox", "ricoh"]),
        (DeviceType.Speaker, ["sonos", "bose", "harman"]),
        (DeviceType.Tv, ["roku", "vizio", "tcl ", "hisense", "lg electronics", "skyworth"]),
        (DeviceType.Network, ["ubiquiti", "routerboard", "mikrotik", "cisco", "netgear", "tp-link", "aruba", "ruckus", "d-link", "zyxel", "juniper"]),
        (DeviceType.Phone, ["xiaomi", "oneplus", "huawei device", "oppo", "vivo mobile", "motorola mobility", "hmd global", "realme"]),
        (DeviceType.Computer, ["intel", "dell", "lenovo", "hewlett", "hp inc", "asustek", "micro-star", "giga-byte", "acer", "framework", "raspberry", "azurewave", "liteon", "realtek"]),
    ];

    public static DeviceType Guess(string? name, string? maker)
    {
        var words = NotWord().Split((name ?? "").ToLowerInvariant());
        foreach (var (type, list) in NameWords)
            if (words.Any(list.Contains)) return type;

        var company = (maker ?? "").ToLowerInvariant() + " ";
        foreach (var (type, parts) in MakerParts)
            if (parts.Any(company.Contains)) return type;
        return DeviceType.Unknown;
    }

    public static string Label(DeviceType type) => type switch
    {
        DeviceType.Phone => "Phone or tablet",
        DeviceType.Computer => "Computer",
        DeviceType.Tv => "TV",
        DeviceType.Camera => "Camera",
        DeviceType.SmartHome => "Smart home device",
        DeviceType.Console => "Games console",
        DeviceType.Printer => "Printer",
        DeviceType.Server => "Server",
        DeviceType.Speaker => "Speaker",
        DeviceType.Network => "Network equipment",
        _ => "Device",
    };
}
