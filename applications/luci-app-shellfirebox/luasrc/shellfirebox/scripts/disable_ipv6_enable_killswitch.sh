#!/bin/sh

# Script to 
# 1) Disable ipv6 
# 2) Enable killswitch

# add entry to /etc/sysctl.conf disable_ipv6
echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.conf
sysctl -p /etc/sysctl.conf 


# remove wan6 interface
uci delete network.wan6
uci commit
/etc/init.d/network restart

# disable dhcp ipv6 options
uci del dhcp.lan.ra
uci del dhcp.lan.dhcpv6
uci commit dhcp
/etc/init.d/odhcpd restart


# change firewall rules to only support ipv4


# remove special ipv6 firewall rules
NAME1=`uci get firewall.@rule[0].name`
NAME2=`uci get firewall.@rule[1].name`
NAME3=`uci get firewall.@rule[2].name`
NAME4=`uci get firewall.@rule[3].name`
NAME5=`uci get firewall.@rule[4].name`
NAME6=`uci get firewall.@rule[5].name`
NAME7=`uci get firewall.@rule[6].name`

CHECK1="Allow-ICMPv6-Forward"
CHECK2="Allow-ICMPv6-Input"
CHECK3="Allow-DHCPv6"
CHECK4="Allow-MLD"

echo "CHECK1: $CHECK1"
echo "CHECK2: $CHECK2"
echo "CHECK3: $CHECK3"
echo "CHECK4: $CHECK4"


echo "NAME1: $NAME1"
echo "NAME2: $NAME2"
echo "NAME3: $NAME3"
echo "NAME4: $NAME4"
echo "NAME5: $NAME5"
echo "NAME6: $NAME6"
echo "NAME7: $NAME7"


if [ "$NAME7" == "$CHECK1" ]
then
	echo "$NAME7"
	CFG=`uci show firewall.@rule[6].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME7" == "$CHECK2" ]
then
	echo "$NAME7"
	CFG=`uci show firewall.@rule[6].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME7" == "$CHECK3" ]
then
	echo "$NAME7"
	CFG=`uci show firewall.@rule[6].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME7" == "$CHECK4" ]
then
	echo "$NAME7"
	CFG=`uci show firewall.@rule[6].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi

if [ "$NAME6" == "$CHECK1" ]
then
	echo "$NAME6"
	CFG=`uci show firewall.@rule[5].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME6" == "$CHECK2" ]
then
	echo "$NAME6"
	CFG=`uci show firewall.@rule[5].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME6" == "$CHECK3" ]
then
	echo "$NAME6"
	CFG=`uci show firewall.@rule[5].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME6" == "$CHECK4" ]
then
	echo "$NAME6"
	CFG=`uci show firewall.@rule[5].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi


if [ "$NAME5" == "$CHECK1" ]
then
	echo "$NAME5"
	CFG=`uci show firewall.@rule[4].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME5" == "$CHECK2" ]
then
	echo "$NAME5"
	CFG=`uci show firewall.@rule[4].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME5" == "$CHECK3" ]
then
	echo "$NAME5"
	CFG=`uci show firewall.@rule[4].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME5" == "$CHECK4" ]
then
	echo "$NAME5"
	CFG=`uci show firewall.@rule[4].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi

if [ "$NAME4" == "$CHECK1" ]
then
	echo "$NAME4"
	CFG=`uci show firewall.@rule[3].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME4" == "$CHECK2" ]
then
	echo "$NAME4"
	CFG=`uci show firewall.@rule[3].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME4" == "$CHECK3" ]
then
	echo "$NAME4"
	CFG=`uci show firewall.@rule[3].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME4" == "$CHECK4" ]
then
	echo "$NAME4"
	CFG=`uci show firewall.@rule[3].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi

if [ "$NAME3" == "$CHECK1" ]
then
	echo "$NAME3"
	CFG=`uci show firewall.@rule[2].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME3" == "$CHECK2" ]
then
	echo "$NAME3"
	CFG=`uci show firewall.@rule[2].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME3" == "$CHECK3" ]
then
	echo "$NAME3"
	CFG=`uci show firewall.@rule[2].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME3" == "$CHECK4" ]
then
	echo "$NAME3"
	CFG=`uci show firewall.@rule[2].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi

if [ "$NAME2" == "$CHECK1" ]
then
	echo "$NAME2"
	CFG=`uci show firewall.@rule[1].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME2" == "$CHECK2" ]
then
	echo "$NAME2"
	CFG=`uci show firewall.@rule[1].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME2" == "$CHECK3" ]
then
	echo "$NAME2"
	CFG=`uci show firewall.@rule[1].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME2" == "$CHECK4" ]
then
	echo "$NAME2"
	CFG=`uci show firewall.@rule[1].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi


if [ "$NAME1" == "$CHECK1" ]
then
	echo "$NAME1"
	CFG=`uci show firewall.@rule[0].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME1" == "$CHECK2" ]
then
	echo "$NAME1"
	CFG=`uci show firewall.@rule[0].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME2" == "$CHECK3" ]
then
	echo "$NAME1"
	CFG=`uci show firewall.@rule[0].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi
if [ "$NAME2" == "$CHECK1" ]
then
	echo "$NAME1"
	CFG=`uci show firewall.@rule[0].name | awk -F "." '{ print $2 }'`
	uci delete firewall.$CFG
fi



echo "ip6tables -P INPUT DROP" >> /etc/firewall.user
echo "ip6tables -P OUTPUT DROP" >> /etc/firewall.user
echo "ip6tables -P FORWARD DROP" >> /etc/firewall.user
echo "ip6tables -A INPUT -j DROP" >> /etc/firewall.user
echo "ip6tables -A OUTPUT -j REJECT" >> /etc/firewall.user
echo "ip6tables -A FORWARD -j REJECT" >> /etc/firewall.user



uci commit firewall
/etc/init.d/firewall restart


uci del firewall.@zone[-1]
uci del firewall.@zone[-1]
uci del firewall.@zone[-1]
uci del firewall.@zone[-1]

uci add firewall zone
uci set firewall.@zone[-1].name='lan'
uci set firewall.@zone[-1].input='ACCEPT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='ACCEPT'
uci set firewall.@zone[-1].network='lan'
uci set firewall.@zone[-1].family='ipv4'

uci add firewall zone
uci set firewall.@zone[-1].name='wan'
uci set firewall.@zone[-1].input='REJECT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='REJECT'
uci set firewall.@zone[-1].masq='1'
uci set firewall.@zone[-1].mtu_fix='1'
uci set firewall.@zone[-1].network='wan wan6'
uci set firewall.@zone[-1].family='ipv4'

uci add firewall zone
uci set firewall.@zone[-1].name='vpn'
uci set firewall.@zone[-1].input='REJECT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='REJECT'
uci set firewall.@zone[-1].masq='1'
uci set firewall.@zone[-1].mtu_fix='1'
uci set firewall.@zone[-1].network='vpn'
uci set firewall.@zone[-1].family='ipv4'


uci set firewall.@zone[-1].family='ipv4'

uci del firewall.@forwarding[-1]
uci del firewall.@forwarding[-1]

uci add firewall forwarding
uci set firewall.@forwarding[-1].dest='vpn'
uci set firewall.@forwarding[-1].src='lan'

uci add firewall forwarding
uci set firewall.@forwarding[-1].dest='wan'
uci set firewall.@forwarding[-1].src='lan'
uci commit firewall
/etc/init.d/firewall restart



uci delete network.@interface[1].ip6assign
uci commit network
/etc/init.d/network restart


rm /usr/lib/lua/luci/shellfirebox/scripts/disable_ipv6_enable_killswitch.sh

/usr/bin/killall -1 openvpn

