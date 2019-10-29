#!/bin/sh
mv /tmp/dhcp-config.hold /etc/config/dhcp
uci set dhcp.@dnsmasq[0].noresolv='0'
uci set dhcp.@dnsmasq[0].server=''
uci commit

/etc/init.d/dnsmasq reload

