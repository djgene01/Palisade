FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq systemd systemd-sysv dbus iproute2 isc-dhcp-client jq curl procps netcat-openbsd unzip iputils-ping >/dev/null \
 && mkdir -p /etc/network/interfaces.d && printf 'source /etc/network/interfaces.d/*\n\n# The internet port is the container own.\niface eth0 inet manual\n' > /etc/network/interfaces \
 && mkdir -p /etc/network/interfaces.d
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
