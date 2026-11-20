# VPN (WireGuard): plan

Agreed with the owner (2026-11-20):

- **Protocol:** WireGuard, in the kernel, configured by the agent.
- **Release 1:** the firewall, a guided wizard, and QR codes or files for the **official WireGuard apps**.
  - Release 2: VPN built into the Android app.
  - Release 3: a WPF tray app for Windows.
- **The owner's line:** a fibre ONT with a public IPv4 address on the firewall itself.
- **Before the VPN can be switched on, Palisade must prove the address is public.**
- **Dynamic DNS:** DuckDNS, optional, since the address may change.
- **Default access:** home and internet. "Internet only" can be chosen per device.
- **Address check:** Cloudflare's trace (`https://1.1.1.1/cdn-cgi/trace`).

## Reachability check (in the engine, not only the wizard)

1. The internet port's IPv4 address is public. It must not be:
   - private (RFC 1918)
   - carrier-grade NAT (100.64.0.0/10)
   - link-local, loopback or documentation ranges
2. Cloudflare's trace sees the same address, so nothing translates in between.

Each outcome has its own plain-language advice:
- **Ready**
- **Not public:** behind another router, or carrier-grade NAT
- **Different:** something translates in between
- **Couldn't ask:** no internet, or Cloudflare unreachable

Switching on runs the check again in the engine and refuses unless it says ready, so a stale tab or an older app can't skip it. The trace address can be overridden (`PALISADE_TRACE_URL`) so tests can cover every outcome.

The check proves the address, not that UDP gets in. The wizard's last step waits for a handshake from a device on mobile data. A handshake arriving from the home network is not taken as proof ("switch to mobile data").

## Firewall

- **Interface and addresses:** `palisade-wg`. The tunnel network defaults to 10.66.0.0/24, with the firewall at .1. The port defaults to UDP 51820.
- **Server key:** generated once into `/etc/palisade/wireguard/server.key`, mode 0600 from creation.
  - It survives switch-off and the 60-second undo, so issued QR codes keep working.
  - It is never in `config.json`, `/config`, `GeneratedFiles` (Advanced shows those), command arguments or logs.
  - The agent combines it with the rendered peer list into a root-only file and runs `wg syncconf`.
- **Device keys (release 1):** each device's private key is made on the firewall, shown once as a QR code or `.conf` file, and never stored. Only the public key is kept.
- **Each device is allowed exactly its own /32.** WireGuard's cryptokey routing then makes the source address trustworthy, so address-matched rules are safe. A spoof test proves it.
- **The port is open from the internet side and from the home side.** A phone at home with the VPN left on reaches the public address through the home port, and must keep working.
- **Same treatment as home devices**, with every `iifname lan` decision made for the tunnel too:
  - the DNS redirect to the filter (ip nat)
  - the 853 reject
  - custom outgoing rules and the relay trap
  - NAT to the internet, which `oifname wan masquerade` already covers
- **Home and internet:** like a home device, including this firewall's pages and SSH, and device names.
- **Internet only:** the internet through the home line and filter, and DNS only. Matched on source address, it is refused:
  - home devices
  - extra networks
  - the holding zone
  - other VPN devices
  - the management ports on every address the firewall holds
- **Not applied to VPN devices in release 1**, because they work by MAC and a tunnel has none. The page says so.
  - pauses and off-times
  - site limits
  - per-device filter levels
  - Zero Trust approval: a VPN device is let in by its key instead
- **dnsmasq** also listens on the tunnel: `interface=palisade-wg` with `bind-dynamic`, so it works before the interface exists, and `no-dhcp-interface=palisade-wg`.

## Engine ownership

- `VpnSettings` lives in `FirewallConfig`, owned by the engine like Zero Trust. A whole-config save keeps it.
- **Through the confirm:** switching on or off, and changing the port or range. The undo removes the interface and closes the port.
- **Adding a device:** immediate. It returns the client config once.
- **Removing a device:** immediate and permanent, with no undo. A lost phone must not come back.
- **Validation runs only while on.** It checks overlap in both directions: the tunnel range against the home network, extra networks and the holding zone.

## DuckDNS

- **The token stays agent-side** (`/var/lib/palisade/ddns.json`, 0600), and the UI sees only `HasToken`. It travels in a URL, so it is never logged or echoed.
- **Updates:** on switch-on, when the address changes, and hourly. The page shows the last result.

## Pages

- **Network → VPN:** a wizard.
  1. Check the line.
  2. Choose a name (DuckDNS, or the fixed address).
  3. Switch on, with the confirm.
  4. Add a device: a QR code, plus a `.conf` download or share, since a phone can't scan its own screen.
  5. Live test: waiting for a handshake from mobile data.
- **Device list:** last handshake, access, remove.
- **Security notes:** a device's private key crosses plain HTTP on 8080 to draw the QR code, once.

## As built (branch `vpn`)

- **Proven with real WireGuard on both ends:** `tests/e2e/vpn.sh`, 54 of 54. The test builds its own small internet: a provider gateway, a server, Cloudflare's trace, two phones out there and one at home.
- **Adding a device without a DuckDNS name checks the line afresh,** and refuses rather than issue settings with an empty or stale address.
- **Sharing the settings file in the app:**
  - Android opens the share sheet, with a fallback of saving to Files and importing from file.
  - Windows saves the file to Downloads and shows it in Explorer.
- **Not in release 1:** changing a device's access (remove and add it again instead), and per-device pauses, limits and filter levels for VPN devices.
- **Not verified here, only on a real line:**
  - a real DuckDNS update
  - importing the QR code or file into the WireGuard app on a phone
  - whether WireGuard appears in Android's share sheet
  - the web's `AgentClient` VPN calls, since the tests drive the agent socket directly

## Tests

- **A second privileged container** plays the remote phone with real `wg`:
  - the tunnel comes up
  - home and internet works, internet only is refused home and management, and the filter applies
  - a spoofed source is dropped
  - removing a device ends access
  - the undo closes everything
  - a phone at home with the VPN on works
- **Secret search:** `config.json`, `/config`, `/status`, the Advanced files and the journal must contain neither private key nor the token.
- **Combined:** with Zero Trust and a per-device filter level.
- **After tagging:** the upgrade from the real v1.7 release, using the published package.
