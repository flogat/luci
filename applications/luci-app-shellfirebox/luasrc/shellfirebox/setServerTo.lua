#!/usr/bin/lua
local shellfirebox = require "luci.shellfirebox"
local serverid = arg[1]
shellfirebox.setServerTo(serverid)    



