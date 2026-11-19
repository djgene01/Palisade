# IPv6 and automatic names: plan

Agreed with the owner (2026-11-19):

- **IPv6 source:** both. A private range (ULA, `fdxx::/64`) at home always; plus the provider's prefix when one is delegated (DHCPv6-PD).
- **Name ending:** `home.arpa` (RFC 8375).
- **Who is named:** every device. The name given on Devices, else the device's own hostname, else maker + short tag (`samsung-3f2a`). Duplicates get `-2`, `-3`.
- **Inbound IPv6:** only ports opened on the Open ports page, to that device's current IPv6 addresses.

IPv6 is **off by default**, switched on under Network with the usual 60-second confirm. When off, every generated file is byte-identical to before.

## Three releases, each proven in the container first

### 1. Names (IPv4 only)

- The engine assigns names and persists them by MAC (`names.json`), so `-2` never swaps between devices.
- **Hostnames are untrusted.** These are reserved and never assigned to a device:
  - `palisade`, which is the firewall itself
  - `wpad`, `localhost`, `isatap`
  - any name already held by another device
- Waiting and blocked devices (Zero Trust) get no name.
- Files and dnsmasq settings:
  - `/etc/palisade/names/hosts` for dnsmasq through `hostsdir`. Check that removed lines really disappear without a SIGHUP, which would clear the cache.
  - `domain=home.arpa`, `local=/home.arpa/` and `dhcp-ignore-names`, so Palisade is the only source of names.
  - The per-level DNS instances (which have `no-hosts`) serve the names too.
- Web: `AllowedHosts` must let the page open as `palisade.home.arpa:8080`.
- UI: each device shows its name, and the name can be copied.

**As built (branch `device-names`):**
- dnsmasq registers no names itself (`dhcp-ignore-names`). It tells devices the domain through DHCP option 15 instead of `domain=`, so `home.arpa` belongs to Palisade alone.
- dnsmasq's lease file turned out to be unreliable for what a device calls itself: dnsmasq takes the name from one device when two claim it, and loses it on a conflict. So `deploy/palisade-lease-name`, run as the `dhcp-script`, saves `DNSMASQ_SUPPLIED_HOSTNAME` (cleaned) to `/var/lib/palisade/hostnames/<mac>`. `GetLeasesAsync` reads it, and seeds it from the lease file the first time, so an upgrade keeps the names it already knew.
- Fixed-address entries (`dhcp-host`) no longer carry a name.
- Proven on real dnsmasq (Debian 12 and 13, Ubuntu 24.04) and with the real agent:
  - names end to end, 20 of 20
  - the v1.5.1 upgrade, 6 of 6
  - Zero Trust still 47 of 47
  - fixed addresses still 8 of 8

### 2. Home IPv6 (private range), with every enforcement twin

Turning on IPv6 forwarding must not open a way around anything that is IPv4-only today:

| Today, IPv4 only | IPv6 twin |
|---|---|
| Extra networks without internet (`ip saddr` range) | Drop IPv6 from those devices to the internet. They share the cable and hear the advertisement, so match by MAC or block their IPv6 entirely. **Blocks the release.** |
| Limits (`ip daddr != @set`, nftset `4#…`) | An `ipv6_addr` set filled by dnsmasq through `6#…`. Fix the restore path in `Limits.cs:97`, which throws on IPv6. |
| DNS redirect (`table ip palisade_nat`) | A `table ip6` nat with the same per-level redirects. |
| Usage sets (`ipv4_addr`) | Count IPv6 too, mapped to the device through the neighbour table. |
| Custom rules with an address, and `Protocol.Icmp` | Decide and document: address rules stay IPv4-only, and port rules apply to both. |
| Zero Trust flows (`ip daddr`) | The drop already covers IPv6. Add IPv6 flows to the list, or document the gap. |
| Relay trap | `address=/x/::` is already rendered. Verify. |

Firewall itself:
- Router advertisements come from dnsmasq (`enable-ra`, `constructor:<lan>`).
- With only the private range there is no default route, so the internet is not advertised over IPv6.
- The firewall keeps accepting ICMPv6.
- Switching off, or an undo after 60 seconds, must withdraw the advertisement (lifetime 0), so clients drop the IPv6 route within seconds.

### 3. Provider prefix and opened ports

- Before choosing a client, find what owns the internet port on each supported install:
  - ifupdown on Debian 12 and 13
  - netplan on Ubuntu
  - the Wi-Fi uplink
- The firewall must keep its own IPv6 default route with forwarding on (`accept_ra=2`).
- Accept DHCPv6 replies on the internet port (udp 547 to 546).
- Never write the delegated prefix into `nftables.conf` or `config.json`: it changes without an apply.
- Opened ports: an `ipv6_addr` set per opened port, filled by the agent from the neighbour table. It is empty at boot and emptied when the port is closed. A second device must not be reachable.
- From the provider side, the home-side global address must not answer on 8080, 22 or 53.
- Test with a fake provider (Kea DHCPv6 in a network namespace):
  - no prefix
  - a /56
  - a /64 only
  - a prefix change

## Engine ownership

The IPv6 setting and the generated private prefix are owned by the engine, like Zero Trust: a whole-config save from an older app or a stale tab keeps them. The prefix is generated once (RFC 4193 random) and kept.

## Combinations to test together

IPv6 with Zero Trust, limits, per-device filter levels and fixed addresses all at once. v1.5.1 happened because a reservation and the hosts file were each proven alone.
