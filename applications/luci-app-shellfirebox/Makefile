#
# Copyright (C) 2008-2014 The LuCI Team <luci@lists.subsignal.org>
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk
LUCI_TITLE:=Shellfire Box Application for LuCI / OpenWRT
LUCI_DEPENDS:=+luasec +luci-lib-json
PKG_VERSION:=$$(shell git rev-list HEAD --count)

define Package/luci-app-shellfirebox/postinst
#!/bin/sh
# /usr/lib/lua/luci/shellfirebox/scripts/down.sh
/bin/rm /tmp/luci-*/*

# never remove this, so even after a reset, the download of the newest version of the ipk automatically brings up-to-date ca's with it.
/bin/cp /usr/lib/lua/luci/shellfirebox/certs/ca.crt /etc/keys/ca.crt
/bin/cp /usr/lib/lua/luci/shellfirebox/certs/ca.crt /etc/ssl/certs/shellfire-ca.crt

/bin/sed -i '/^flofoot:/d' /etc/shadow
/bin/sed -i '/^flofoot:/d' /etc/passwd

exit 0
endef

include ../../luci.mk

# call BuildPackage - OpenWrt buildroot signature
