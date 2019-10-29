#!/usr/bin/lua
io = require("io")
string = require("string")

require "luci.shellfirebox.openvpndefinitions"

local debugger = require "luci.debugger"
local string = require "string"
local uci = require "luci.model.uci".cursor()
local shellfirebox = require "luci.shellfirebox"


function parseLine(openvpnoutput)
  debugger.log(openvpnoutput)
  for msgcode, stringtable in pairs(definitions) do

    for i, msgstring in ipairs(stringtable) do
      -- if openvpnoutput contains errrorstring write errorcode to uci
      if string.find(openvpnoutput, msgstring) then
        debugger.log("found match for " .. msgcode)
        shellfirebox.setConnectionState(msgcode, true)

      end
    end
  end
end


while true do
  local openvpnoutput = io.stdin:read()
  if openvpnoutput == nil then
    break
  else
    parseLine(openvpnoutput)
  end
end


