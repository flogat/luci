#!/usr/bin/lua
io = require("io")
string = require("string")

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

function getWireguardStatus()
  local data = { }
  local last_device = ""

  local wg_dump = io.popen("wg show all dump")
  if wg_dump then
    local line
    for line in wg_dump:lines() do
      local line = string.split(line, "\t")
      if not (last_device == line[1]) then
        last_device = line[1]
        data[line[1]] = {
          name                 = line[1],
          public_key           = line[3],
          listen_port          = line[4],
          fwmark               = line[5],
          peers                = { }
        }
      else
        local peer = {
          public_key           = line[2],
          endpoint             = line[4],
          allowed_ips          = { },
          latest_handshake     = line[6],
          transfer_rx          = line[7],
          transfer_tx          = line[8],
          persistent_keepalive = line[9]
        }
        if not (line[4] == '(none)') then
          for ipkey, ipvalue in pairs(string.split(line[5], ",")) do
            if #ipvalue > 0 then
              table.insert(peer['allowed_ips'], ipvalue)
            end
          end
        end
        table.insert(data[line[1]].peers, peer)
      end
    end
  end

  return data["wg0"]
end




local lastdata
local data

while true do
  data = getWireguardStatus()

  if lastdata == nil and data ~= nil then
    debugger.log("connection state change detected, now connected!")
    shellfirebox.setConnectionState("succesfulConnect", true)
  end

  if lastdata ~= nil and data == nil then
    debugger.log("connection state change detected, now disconnected!")
    shellfirebox.setConnectionState("processDisconnected", true)
    break
  end

  lastdata = data  

  luci.sys.exec("sleep 1")
end


