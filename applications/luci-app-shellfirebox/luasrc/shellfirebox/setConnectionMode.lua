#!/usr/bin/lua
local shellfirebox = require "luci.shellfirebox"
local connectionMode = arg[1]
shellfirebox.setConnectionMode(connectionMode)    



