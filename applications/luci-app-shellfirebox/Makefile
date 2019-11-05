#
# Copyright (C) 2008-2014 The LuCI Team <luci@lists.subsignal.org>
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk
LUCI_TITLE:=Shellfire Box Application for LuCI / OpenWRT
LUCI_DEPENDS:=+luasec +luci-lib-json
PKG_VERSION:=$$(shell git rev-list HEAD --count)

include ../../luci.mk

# call BuildPackage - OpenWrt buildroot signature
