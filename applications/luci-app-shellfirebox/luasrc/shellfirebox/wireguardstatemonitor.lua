#!/usr/bin/lua
io = require("io")
string = require("string")

local debugger = require "luci.debugger"
local string = require "string"
local uci = require "luci.model.uci".cursor()
local shellfirebox = require "luci.shellfirebox"

function isWanConnected()
  local wan_dump = io.popen("cat /sys/class/net/eth0/carrier")

  if wan_dump then
    local line
    for line in wan_dump:lines() do
      if line == "1" then
        return true
      end
    end
  end

  return false
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




local data
local wanconnected
local currentStatusConnected

while true do
  data = getWireguardStatus()
  wanconnected = isWanConnected()
  currentStatusConnected = shellfirebox.getConnectionState() == "succesfulConnect"

  if shellfirebox.getConnectionState() == "connectionModeChange" then
    do return end
  end

  if currentStatusConnected == false and wanconnected == true and data ~= nil then
    debugger.log("connection state change detected, now connected!")
    shellfirebox.setConnectionState("succesfulConnect", true)
    shellfirebox.callWireguardUpScript()
  end

  if currentStatusConnected == true and data == nil then
    debugger.log("connection state change detected, now disconnected!")
    shellfirebox.callWireguardDownScript()
    shellfirebox.setConnectionState("processDisconnected", true)
  end

  if currentStatusConnected == true and wanconnected == false then
    debugger.log("wan not connected anymore, now disconnected!")
    shellfirebox.callWireguardDownScript()
    shellfirebox.setConnectionState("processDisconnected", true)
  end

  luci.sys.exec("sleep 1")

end


