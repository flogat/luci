#!/bin/sh

IP1=`echo $foreign_option_1 | awk '{split($0,array," ")} END{print array[3]}'`

IP2=`echo $foreign_option_2 | awk '{split($0,array," ")} END{print array[3]}'`

IP3=`echo $foreign_option_3 | awk '{split($0,array," ")} END{print array[3]}'`

echo "foreign options 1: $foreign_option_1"
echo "foreign options 2: $foreign_option_2"
echo "foreign options 3: $foreign_option_3"

echo "DNS IP1: $IP1"
echo "DNS IP2: $IP2"
echo "DNS IP3: $IP3"

cp /etc/config/dhcp /tmp/dhcp-config.hold

if [ ! -z "$IP1" ]; then
  eval "uci add_list dhcp.@dnsmasq[0].server='$IP1'"
fi
if [ ! -z "$IP2" ]; then
  eval "uci add_list dhcp.@dnsmasq[0].server='$IP2'"
fi
if [ ! -z "$IP3" ]; then
  eval "uci add_list dhcp.@dnsmasq[0].server='$IP3'"
fi

uci set dhcp.@dnsmasq[0].noresolv='1'

uci commit
/etc/init.d/dnsmasq reload
