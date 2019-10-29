#!/usr/bin/lua
local shellfirebox = require "luci.shellfirebox"
local debugger = require "luci.debugger"


if shellfirebox.getAutostartRequested() == "true" then
  debugger.log("autostarter - autostartRequested is true, so connecting")
  shellfirebox.connectAsync()
else
  debugger.log("autostarter - autostartRequested is false, so doing nothing")
end
    
