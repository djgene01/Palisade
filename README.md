# Palisade

**A home firewall you set up and run from your browser.** Install it on a spare PC with two network ports. It sits between your modem and your home network, hands out addresses, filters what your devices can reach, and shows who is using the internet. No command line is needed after the install.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/djgene01/Palisade)](https://github.com/djgene01/Palisade/releases/latest)

```
   Internet
      │
  ┌───┴────┐
  │ Modem  │
  └───┬────┘
      │  internet port
  ┌───┴────────────┐
  │    Palisade    │  firewall, NAT, DHCP, DNS, filter
  └───┬────────────┘
      │  home network port
  ┌───┴────────────┐
  │ Switch / Wi-Fi │──── your devices
  └────────────────┘
```

---

## Contents

- [What it does](#what-it-does)
- [What you need](#what-you-need)
- [Install on Debian](#install-on-debian)
- [Install on Ubuntu Server](#install-on-ubuntu-server)
- [First-time setup](#first-time-setup)
- [The companion app](#the-companion-app)
- [Updating](#updating)
- [Troubleshooting](#troubleshooting)
- [Uninstalling](#uninstalling)
- [How it works](#how-it-works)
- [Security notes](#security-notes)
- [Building from source](#building-from-source)
- [License](#license)

---

## What it does

**Protects the network**
- A stateful firewall (nftables) that drops everything from the internet you did not ask for.
- Shares one internet connection with every device (NAT).
- Port forwarding, plus your own allow and block rules.
- A safety net: after any change you have 60 seconds to confirm you can still reach the firewall. If you can't, the change is undone automatically.

**Runs the home network**
- Hands out addresses (DHCP), with fixed addresses for chosen devices.
- Answers name lookups (DNS). The *Flush DNS* button clears remembered answers.
- Extra address ranges on the same cable, for example cameras with fixed addresses, with or without internet access.
- The internet side can be a cable or the machine's own Wi-Fi. A spare port can be a *maintenance port* that reaches only the firewall's page.

**Filters content**
- Network-wide filter levels: **Security** (malware and phishing), **Adult** (plus adult content) and **Family** (plus mixed content). Each device can have its own level.
- Sites nobody may open, and sites that always open.
- Per-device site limits, for example a TV box that may only reach YouTube.
- Blocks services that rent your connection out to strangers ("bandwidth sharing" SDKs hidden in cheap TV boxes and free apps).
- Stops browsers from skipping the filter with their own encrypted DNS.

**Shows what's happening**
- Who is using the internet right now, with totals for the last 3 and 7 days.
- Devices listed with names, type icons and maker.
- **Where to?** briefly records which sites one device connects to.
- Pause a device, or give it off times such as school nights.

**Looks after itself**
- Updates itself from this repository's [releases](https://github.com/djgene01/Palisade/releases), at night, when you turn on automatic updates.
- Keeps working after a reboot, even before its own programs have started: the rules are loaded at boot by the system.

---

## What you need

| | |
|---|---|
| **Computer** | Any 64-bit x86 PC (`x86_64`/`amd64`). Mini PCs and old desktops work well. ARM boards such as the Raspberry Pi are **not** supported yet. |
| **Network ports** | **Two**: one to the modem (*internet port*), one to your switch or access point (*home network port*). A USB Ethernet adapter can be the second port. The internet side may also be Wi-Fi. |
| **Operating system** | **Debian 12 or 13**, a minimal install with no desktop (recommended), **or** **Ubuntu Server 24.04 / 22.04** after a few extra steps. |
| **Disk** | The release download is about 100 MB. Everything else Palisade needs comes from the standard package repositories. |

> **Note:** Palisade replaces the machine's firewall rules and manages the home network port's address. Use a machine dedicated to this job, not one that also runs Docker, a VPN server or other network software.

---

## Install on Debian

Debian 12 (bookworm) and 13 (trixie) are the main targets of the installer.

### 1. Install Debian

Install Debian from the *netinst* image with these choices:

- **Network:** pick the port that goes to your **modem** as the primary network interface, so the machine has internet during the install.
- **Software selection:** untick *Debian desktop environment* and every desktop. Tick **SSH server** (optional, handy for later) and **standard system utilities**.

A minimal install like this manages its ports with `ifupdown` (`/etc/network/interfaces`), which is what Palisade expects.

> **Note:** If you used a desktop or cloud image that uses NetworkManager or systemd-networkd instead, install `ifupdown` (`apt install ifupdown`). Make sure NetworkManager does not manage the home network port. The [Ubuntu steps](#install-on-ubuntu-server) show the same idea.

### 2. Download and install Palisade

Log in on the machine (or over SSH) and become root:

```bash
su -
```

Download the latest release, unpack it and run the installer:

```bash
apt-get update && apt-get install -y wget ca-certificates
cd /root
wget https://github.com/djgene01/Palisade/releases/latest/download/palisade-linux-x64.tar.gz
tar -xzf palisade-linux-x64.tar.gz
sh palisade/install.sh
```

The installer:

- installs `nftables`, `dnsmasq` and the libraries Palisade needs
- copies the programs to `/opt/palisade`
- starts two services, `palisade-agent` and `palisade-web`

When it finishes it prints the address to open, for example:

```
Palisade is running. Open one of these in a browser on the same network:
  http://192.168.1.23:8080   (port enp1s0)

Until you finish the setup page, this machine filters nothing.
```

Continue with [First-time setup](#first-time-setup).

---

## Install on Ubuntu Server

Ubuntu sets up its network ports with **netplan** rather than `ifupdown`. Palisade needs `ifupdown` to bring the home network port back up at boot. These steps make the two work side by side: netplan keeps the internet port, and Palisade looks after the home network port.

> ⚠️ **Do steps 2–4 on the machine's own keyboard and screen, not over SSH.** You are changing which ports are configured, and a typo can cut off a remote session.

These steps were checked on Ubuntu Server 24.04 (installer run, setup applied, and the home port restored by `ifupdown`). The same packages are present on 22.04. Ubuntu Desktop uses NetworkManager and is not covered here.

### 1. Find your port names

```bash
ip -br link
```

You will see names such as `enp1s0` and `enp2s0`. Work out which one is plugged into the **modem** (it usually has an address: `ip -br addr`). In the steps below:

- `WAN` stands for the **internet port**, for example `enp1s0`
- `LAN` stands for the **home network port**, for example `enp2s0`

Replace them with your own names.

### 2. Install ifupdown

```bash
sudo apt-get update
sudo apt-get install -y ifupdown wpasupplicant wget ca-certificates
```

`wpasupplicant` is only needed if the internet side will be Wi-Fi, but it does no harm.

### 3. Let netplan configure only the internet port

The Ubuntu installer often configures **every** port. Look at the netplan files:

```bash
ls /etc/netplan/
sudo cat /etc/netplan/*.yaml
```

Edit the file (often `50-cloud-init.yaml` or `00-installer-config.yaml`) so only the **internet port** is listed:

```yaml
network:
  version: 2
  ethernets:
    enp1s0:          # your WAN port
      dhcp4: true
```

Remove the home network port (`LAN`) from the file completely. Palisade gives it its address.

If the file is called `50-cloud-init.yaml`, stop cloud-init from rewriting it at the next boot:

```bash
echo 'network: {config: disabled}' | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
```

Apply the change:

```bash
sudo netplan apply
```

Check that the internet still works (`ping -c 3 debian.org`) and that the `LAN` port now has no address (`ip -br addr`).

### 4. Tell Palisade the internet port is already set up

Palisade normally sets up the internet port itself. On Ubuntu, netplan already does that, so add this line to tell Palisade to leave the port alone. Replace `enp1s0` with your `WAN` port:

```bash
printf '\n# The internet port is set up by netplan.\niface enp1s0 inet manual\n' | sudo tee -a /etc/network/interfaces
```

`/etc/network/interfaces` should now end like this:

```
source /etc/network/interfaces.d/*

# The internet port is set up by netplan.
iface enp1s0 inet manual
```

> **Note:** Use the *maintenance port* or *Wi-Fi* options on Palisade's Network page only if you are comfortable with `ifupdown`. On Ubuntu, any port that Palisade looks after must not also be listed in netplan.

### 5. Turn off ufw

Palisade writes its own firewall rules, and Ubuntu's `ufw` would fight with them:

```bash
sudo ufw disable
```

### 6. Install Palisade

```bash
cd ~
wget https://github.com/djgene01/Palisade/releases/latest/download/palisade-linux-x64.tar.gz
tar -xzf palisade-linux-x64.tar.gz
sudo sh palisade/install.sh
```

The installer prints the address to open. Continue with [First-time setup](#first-time-setup).

> **Note:** The installer may print that `dnsmasq` failed to start. That is expected: Ubuntu's DNS service (`systemd-resolved`) holds `127.0.0.53`, and dnsmasq stays switched off until setup anyway. Once set up, Palisade's dnsmasq listens only on the home network port, and the two run side by side without any change to `systemd-resolved`.

---

## First-time setup

1. **Open the address the installer printed** (`http://<address>:8080`) from a computer on the **modem's** network. Until setup is done, the home network port has no address yet, so this is the way in.

2. **Choose a password** of at least 10 characters. This is the only account.

3. **Answer three questions:**
   1. *Which port goes to the internet?* The cable to your modem or upstream router.
   2. *Which port do your devices plug into?* The cable to your switch or Wi-Fi access point.
   3. *What address should the firewall use on your network?* The suggestion `192.168.50.1` works for most homes. Devices get addresses from `.100` to `.200`.

   Because you are connected from the modem's side, **Allow managing the firewall from the internet side** is already switched on. Leave it on for now, or the page stops working for you as soon as protection starts.

4. **Press _Turn on protection_.** Palisade applies the settings and checks that your browser can still reach it. If it can't within **60 seconds**, the change is undone automatically and nothing is lost.

5. **Plug your switch or access point into the home network port.** Your devices get addresses from Palisade, and the firewall's page is now also at `http://192.168.50.1:8080` (or the address you chose).

6. **Close the side door.** From a device on your home network, go to **Network → Internet side** and switch **Allow managing the firewall from the internet side** off. The Overview page reminds you while it is on.

From here everything is done in the browser: **Overview**, **Devices**, **Content filter**, **Rules**, **Open ports**, **Network** and **Advanced**.

---

## The companion app

The Palisade app for Android and Windows does everything the firewall's own page does: pause a device, change the content filter, open a port, and the rest. It works from your home network. It is not published in an app store yet, so for now you build it yourself (see [Building from source](#building-from-source)).

**Link a phone or tablet:**

1. On a computer, open the firewall's page and go to **Advanced → Phones and tablets**, then choose **Link a phone**. A QR code and an 8-character code appear, valid for 5 minutes.
2. In the app, choose **Link your firewall** and **Scan the code**.
   - Or choose **Type the address and code**. Enter the address shown on the page (such as `192.168.50.1`), check that the fingerprint the app shows matches the one on the page, then type the code.
3. The phone appears in the firewall's list of linked devices. Remove it there at any time, or unlink it from the app's **Firewalls** screen.

The app can link several firewalls and switch between them. **Try the demo** shows a pretend network inside the app, for looking around.

**On Android you can also:**

- **Scan with the phone's own camera.** If your camera app offers to open the code on the firewall's page, it opens Palisade ready to link. Palisade then shows the address and fingerprint to check against the page before anything is sent.
- **Share a page to Palisade.** In the browser, choose **Share → Block or allow in Palisade**. The app shows the site's name and lets you block it for everyone or always allow it.
- **Use the shortcuts on the app icon.** Long-press the icon for **Pause a device** and **Content filter**.

**Lock the app.** In **Firewalls → This device**, switch on **Lock Palisade**. It then asks for your fingerprint, face or screen lock (Windows Hello on Windows) when it opens, and when you come back to it after a minute away.

> **Note:** After a change, the app checks for a few seconds that it can still reach the firewall, then keeps the change. Stay in the app until it says **Saved**. If you leave too early, the firewall undoes the change after a minute, as it does whenever it can't be sure you are not locked out.

---

## Updating

**From the web page.** Go to **Advanced → Palisade updates**. Press **Check now**, then **Install** when a new release is shown. Or switch on **Install new releases automatically**: the firewall then checks this repository's releases every night at about 3 o'clock and installs a new one by itself. Installing restarts Palisade for a few seconds. Your devices stay online and your settings are kept.

**By hand.** Download the newest release and run the installer again, exactly as for the first install. It replaces the programs and keeps your settings:

```bash
cd /root      # or ~ on Ubuntu
rm -rf palisade palisade-linux-x64.tar.gz
wget https://github.com/djgene01/Palisade/releases/latest/download/palisade-linux-x64.tar.gz
tar -xzf palisade-linux-x64.tar.gz
sh palisade/install.sh        # sudo sh palisade/install.sh on Ubuntu
```

---

## Troubleshooting

**Is everything running?**

```bash
systemctl status palisade-agent palisade-web dnsmasq nftables
```

**What went wrong?**

```bash
journalctl -u palisade-agent -n 100 --no-pager
journalctl -u palisade-web -n 100 --no-pager
```

**See the rules and settings Palisade generated:**

```bash
nft list ruleset
cat /etc/dnsmasq.d/palisade.conf
```

The same files are shown on the **Advanced** page.

**I forgot the password.** On the machine, delete the stored password and restart the web interface. The next visit asks you to choose a new one. Your network settings are not touched.

```bash
rm /var/lib/palisade-web/auth.json
systemctl restart palisade-web
```

**I locked myself out.** Changes that cut you off are undone after 60 seconds. If you are still locked out, use the machine's own keyboard and screen. Palisade's rules always allow the web page (8080) and SSH (22) from the home network port. Plug a computer in there.

**Devices get no address.** Check that the home network port is the one plugged into your switch (**Network → Which port is which**). Also check that no other device on that network hands out addresses, such as an ISP router in router mode or a mesh system that is not in access-point mode.

**Ubuntu: the home network port loses its address after a reboot.** Check that `ifupdown` is installed and that the port is **not** listed in any file in `/etc/netplan/` (see [step 3](#3-let-netplan-configure-only-the-internet-port)).

---

## Uninstalling

> ⚠️ This turns the firewall off. Devices behind it lose their internet connection until something else takes over.

```bash
systemctl disable --now palisade-web palisade-agent dnsmasq
for level in off security adult family; do systemctl disable --now "palisade-dns@$level" 2>/dev/null; done
nft flush ruleset
printf '#!/usr/sbin/nft -f\nflush ruleset\n' > /etc/nftables.conf

rm -f /etc/systemd/system/palisade-agent.service /etc/systemd/system/palisade-web.service /etc/systemd/system/palisade-dns@.service
rm -f /etc/dnsmasq.d/palisade.conf /etc/sysctl.d/90-palisade.conf
rm -f /etc/network/interfaces.d/palisade-*
rm -rf /opt/palisade /etc/palisade /var/lib/palisade /var/lib/palisade-web
systemctl daemon-reload
userdel palisade
```

If you set up the internet side as Wi-Fi from Palisade, your original `/etc/network/interfaces` is saved as `/etc/network/interfaces.before-palisade`.

---

## How it works

Palisade is two small programs and two standard system tools.

| Part | Runs as | Job |
|---|---|---|
| **palisade-web** | unprivileged user `palisade` | The web interface on port **8080**, and the companion app's encrypted interface on port **8443**. It cannot change the system. It can only send a whole new configuration to the agent. |
| **palisade-agent** | root | Listens only on a Unix socket (`/run/palisade/agent.sock`) that the web user may open. It checks a configuration, writes the system files and applies them. It accepts whole configurations, never commands. |
| **nftables** | system | The firewall and NAT rules. Loaded at boot by `nftables.service` from `/etc/nftables.conf`, so the network is protected even before Palisade starts. |
| **dnsmasq** | system | Addresses (DHCP) and name lookups (DNS) for the home network. Devices with their own filter level get their own instance (`palisade-dns@<level>`). |

Every change follows the same path:

1. The configuration is checked: are the values valid, and are the ports and ranges safe?
2. The candidate files are tested (`nft -c`, `dnsmasq --test`).
3. The files are applied.
4. The agent checks that DNS still answers.
5. The browser has 60 seconds to prove a fresh connection still gets through. If anything fails, the previous settings go back.

**Files Palisade owns:**

| Path | What |
|---|---|
| `/opt/palisade/` | The programs and the installed `VERSION` |
| `/var/lib/palisade/` | Settings (`config.json`), usage totals, update settings |
| `/var/lib/palisade-web/` | Admin password hash, session keys, the app certificate (`tls.pfx`) and linked devices (`devices.json`) |
| `/etc/nftables.conf` | Firewall rules (rewritten by Palisade) |
| `/etc/dnsmasq.d/palisade.conf`, `/etc/palisade/dns/` | DHCP and DNS settings |
| `/etc/network/interfaces.d/palisade-*` | Home network port, and the internet port or Wi-Fi when Palisade looks after them |
| `/etc/sysctl.d/90-palisade.conf` | Turns on packet forwarding |

**Content filtering** uses free public filtering DNS services: Cloudflare for Families for *Security* and *Adult*, and CleanBrowsing's family filter for *Family*. When filtering is on, devices' DNS lookups are sent through the firewall, so a device can't pick its own DNS server. Filtering works on site names. It does not inspect traffic, and it can't block something inside an app that is already allowed.

---

## Security notes

- The web interface uses **plain HTTP** on port 8080 and has a **single admin password**. Use it only from your home network. Management from the internet side is **off** by default, and should stay off unless the internet side is a network you trust.
- The password is stored as a salted PBKDF2-SHA256 hash. Repeated wrong passwords slow down further attempts.
- The web interface runs as an unprivileged, sandboxed systemd service with no capabilities. Only the agent runs as root, and it only accepts complete configurations, which are validated before any file is written.
- The companion app connects on port **8443** over HTTPS, using a certificate the firewall makes for itself on first start. Only the app's interface answers there, and that interface never answers over plain HTTP.
- **Linking a phone.** You link a phone from **Advanced → Phones and tablets** while signed in. That shows a one-time code that lasts 5 minutes and is thrown away after 5 wrong guesses. The app checks the firewall's key fingerprint, then receives its own token. Only a hash of each token is stored, and you can remove any linked device there, which shuts it out at once.
- From the home network port, the firewall itself accepts only the web interface (8080/8081), the app interface (8443), SSH (22), DHCP, DNS and ping. From the internet side it accepts only ping, unless you allow management from there.

Found a security problem? Please open an issue without the details and ask for a private contact, or use GitHub's private vulnerability reporting if it is enabled.

---

## Building from source

**You need** the [.NET 10 SDK](https://dotnet.microsoft.com/download) and [Node.js](https://nodejs.org/) 22 or newer. Node is only used at build time, to compile the stylesheet with Tailwind. The build runs `npm install` by itself the first time.

```bash
git clone https://github.com/djgene01/Palisade.git
cd Palisade
dotnet test tests/Palisade.Core.Tests
dotnet test tests/Palisade.Web.Tests
dotnet test tests/Palisade.Client.Tests
```

Name the test projects as shown. A plain `dotnet test` at the top also builds the companion app, which needs the .NET MAUI workload (`dotnet workload install maui`). The client tests start the real web interface on free local ports and talk to it over HTTPS.

**The companion app** (`src/Palisade.App`) needs the MAUI workload. On Windows it builds for Windows and Android (iOS and macOS need a Mac):

```bash
dotnet build src/Palisade.App -f net10.0-windows10.0.19041.0
dotnet build src/Palisade.App -f net10.0-android -t:Run     # on a running emulator or a connected phone
```

**Run the web interface on your own computer.** On Windows or macOS it uses a simulated firewall, so you can try every page safely:

```bash
dotnet run --project src/Palisade.Web
```

Then open `http://localhost:8080`. Data is kept in `src/Palisade.Web/data/`.

**Build a release package for a firewall:**

- On Windows: `./deploy/publish.ps1`. The package lands in `release/palisade`.
- On Linux, the same steps as the [release workflow](.github/workflows/release.yml):

  ```bash
  out=release/palisade
  dotnet publish src/Palisade.Agent -c Release -r linux-x64 --self-contained -o "$out/agent"
  dotnet publish src/Palisade.Web   -c Release -r linux-x64 --self-contained -o "$out/web"
  cp deploy/install.sh deploy/*.service "$out/"
  echo dev > "$out/VERSION"
  ```

Copy the folder to the firewall and run `sh install.sh` inside it. A build marked `dev` is not replaced by automatic updates.

**Publish a release.** Push a tag such as `v1.3`. GitHub Actions runs the tests, builds `palisade-linux-x64.tar.gz` and publishes it as a release. Firewalls with automatic updates install it by themselves.

```bash
git tag v1.3
git push origin v1.3
```

**Project layout**

```
src/Palisade.Core     Configuration model, validation and the generators for nftables and dnsmasq (no system access)
src/Palisade.Agent    The root service: applies configurations, reads usage, installs updates
src/Palisade.UI       The screens and stylesheet, shared by the web interface and the companion app
src/Palisade.Web      The web interface host: sign-in, setup, the app interface and phone pairing, and the connection to the agent
src/Palisade.Client   How the app reaches a real firewall: pairing links, the pinned HTTPS connection, RemoteBackend
src/Palisade.App      The companion app (.NET MAUI Blazor Hybrid) for Android and Windows
tests/                Core unit tests, the web interface run in memory, and the client against a running web interface
deploy/               Installer, systemd units and the Windows publish script
```

---

## License

Palisade is released under the [MIT License](LICENSE).
