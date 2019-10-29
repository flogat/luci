#!/bin/sh
echo "----- performing opkg update ----- "
date
opkg update 

echo "the following packages will be upgraded:"
opkg list-upgradable

echo "updating all upgradable packages"
opkg list-upgradable | awk -F ' - ' '{print $1}' | xargs -r opkg upgrade

echo "------ opkg update finished -------"

rm -rf /tmp/luci-*

echo "---- list of all cronjobs ----"
crontab -l
echo "---- end list of all cronjobs ----"
date
