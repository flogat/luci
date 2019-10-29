#
# Copyright (C) 2008-2014 The LuCI Team <luci@lists.subsignal.org>
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk
PO:=luci-app-shellfirebox
LUCI_TITLE:=Shellfire Box Application for LuCI / OpenWRT
LUCI_DEPENDS:=+luasec +luci-lib-json

PKG_VERSION:=$$(shell git rev-list HEAD --count)

define Package/luci-app-shellfirebox/postinst
#!/bin/sh
/bin/cp /usr/lib/lua/luci/view/themes/shellfirebox/header-bootstrap.htm /usr/lib/lua/luci/view/themes/bootstrap/header.htm
/usr/bin/lua /usr/lib/lua/luci/shellfirebox/refreshServerList.lua
/bin/chmod +x /usr/lib/lua/luci/shellfirebox/scripts/disable_ipv6_enable_killswitch.sh
/usr/lib/lua/luci/shellfirebox/scripts/disable_ipv6_enable_killswitch.sh
exit 0
endef

include ../../luci.mk

# call BuildPackage - OpenWrt buildroot signature
