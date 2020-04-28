#!/bin/sh

IP1="8.8.8.8"
IP2="8.8.4.4"
echo "DNS IP1: $IP1"
echo "DNS IP2: $IP2"

cp /etc/config/dhcp /tmp/dhcp-config.hold

eval "uci add_list dhcp.@dnsmasq[0].server='$IP1'"
eval "uci add_list dhcp.@dnsmasq[0].server='$IP2'"
uci set dhcp.@dnsmasq[0].noresolv='1'
uci commit
/etc/init.d/dnsmasq reload
