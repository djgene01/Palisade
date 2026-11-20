#!/bin/sh
# Installs Palisade on a clean Debian 12 or 13 machine. Run as root from the unpacked release folder:
#   sh install.sh
# Safe to run again to upgrade: it replaces the programs and keeps your settings.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run this as root (su -, then: sh install.sh)." >&2
    exit 1
fi

here="$(cd "$(dirname "$0")" && pwd)"
for part in agent web; do
    if [ ! -d "$here/$part" ]; then
        echo "Missing the '$part' folder next to install.sh. Unpack the whole release first." >&2
        exit 1
    fi
done

echo "Installing nftables, dnsmasq, tcpdump and WireGuard..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
# libicu is what .NET uses for text handling; the package name carries a version number, so match it.
# tcpdump records what devices waiting for approval send, while Zero Trust Mode is on.
apt-get install -y -q nftables dnsmasq iproute2 ca-certificates tcpdump curl wireguard-tools "$(apt-cache --names-only search '^libicu[0-9]+$' | awk '{print $1}' | sort -V | tail -n 1)"

# dnsmasq must stay quiet until Palisade has been set up, otherwise it would answer on every port.
# On an upgrade it is already serving the home network, so leave it running.
if [ ! -f /var/lib/palisade/config.json ]; then
    systemctl disable --now dnsmasq >/dev/null 2>&1 || true
fi

if ! id palisade >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin palisade
fi

echo "Copying programs to /opt/palisade..."
systemctl stop palisade-web palisade-agent 2>/dev/null || true
mkdir -p /opt/palisade
rm -rf /opt/palisade/agent /opt/palisade/web
cp -r "$here/agent" "$here/web" /opt/palisade/
# Records which release this is, so the firewall can tell when a newer one is published.
if [ -f "$here/VERSION" ]; then cp "$here/VERSION" /opt/palisade/VERSION; else echo dev > /opt/palisade/VERSION; fi
chown -R root:root /opt/palisade
chmod 755 /opt/palisade/agent/Palisade.Agent /opt/palisade/web/Palisade.Web

install -m 644 "$here/palisade-agent.service" "$here/palisade-web.service" "$here/palisade-dns@.service" "$here/palisade-capture.service" /etc/systemd/system/
# dnsmasq runs this for each lease, so Palisade learns what each device calls itself.
install -m 755 "$here/palisade-lease-name" /opt/palisade/palisade-lease-name
systemctl daemon-reload

# nftables.service reloads the saved rules at every boot, before and without Palisade's own programs.
systemctl enable nftables >/dev/null
systemctl enable --now palisade-agent palisade-web >/dev/null

echo
echo "Palisade is running. Open one of these in a browser on the same network:"
ip -4 -o addr show scope global | awk '{split($4, a, "/"); print "  http://" a[1] ":8080   (port " $2 ")"}'
echo
if [ -f /var/lib/palisade/config.json ]; then
    echo "Upgraded. Your settings were kept and are back in force."
else
    echo "Until you finish the setup page, this machine filters nothing."
fi
