-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Copyright 2008 Jo-Philipp Wich <jow@openwrt.org>
-- Licensed to the public under the Apache License 2.0.

module("luci.controller.shellfirebox", package.seeall)
local shellfirebox = require "luci.shellfirebox"
local ajax = require "luci.shellfirebox.ajax_handler"
local uci = require "luci.model.uci".cursor()
local debugger = require "luci.debugger"

function index()
  entry ( {"admin", "services", "shellfirebox"}, template("shellfirebox/main"), _("Shellfire Box") )
  entry( {"admin", "services", "shellfirebox", "ajax_handler"}, call("handleAjax") )
  entry( {"admin", "services", "shellfirebox", "connect"}, call("connect") )
  entry( {"admin", "services", "shellfirebox", "disconnect"}, call("disconnect") )
  entry( {"admin", "services", "shellfirebox", "abort"}, call("abort"))
  entry( {"admin", "services", "shellfirebox", "setServerTo"}, call("setServerTo"))
  entry( {"admin", "services", "shellfirebox", "doDownloadFirmware"}, call("doDownloadFirmware"))
  
  local shellfirebox = require "luci.shellfirebox"
  if not luci.sys.user.getpasswd("root") then
    entry( {"admin", "services", "shellfirebox", "toggleAdvancedMode"}, call("toggleAdvancedMode")).sysauth = false
  else
    entry( {"admin", "services", "shellfirebox", "toggleAdvancedMode"}, call("toggleAdvancedMode"))
  end
  
  entry( {"admin", "services", "shellfirebox", "toggleLanguage"}, call("toggleLanguage"))
  entry( {"admin", "services", "shellfirebox", "sendLogToShellfire"}, call("sendLogToShellfire"))
  
end

function connect()
  shellfirebox.connectAsync()
  luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shellfirebox"))
end

function disconnect()
  shellfirebox.disconnect()
  luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shellfirebox"))
end

function abort()
  -- if changing server, abort the server change
  if shellfirebox.getConnectionState() == "serverChange" then
    shellfirebox.abortSetServer()
  else
    -- otherwise kill the openvpn process / disconnect
    shellfirebox.disconnect()
   end
   luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shellfirebox"))
end

function setServerTo()
  local serverId = luci.http.formvalue("server")
  shellfirebox.setServerToAsync(serverId)
  luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shellfirebox"))
end

function doDownloadFirmware()
  local filepath = "/tmp/ShellfireTeamspeakTutorial.pdf"
  luci.sys.exec("rm -rf " .. filepath)
  luci.sys.exec("wget -P /tmp https://www.shellfire.de/docs/ShellfireTeamspeakTutorial.pdf")

  local expectedSize = 1034520
  local actualSize = shellfirebox.fsize(filepath)

  if expectedSize == actualSize then
    -- luci.sys.exec("sysupgrade -c -v " .. filepath)
    debugger.log("########## YAY ############# WOULD DEFINIETLY FLASH THE DOWNLOADED ROM NOW! ##############")

  else
    debugger.log("expectedSize=" .. tostring(expectedSize) .. " but actualSize=" .. tostring(actualSize) .. " - not performing sysupgrade")
  end

  luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shellfirebox"))
end


function sendLogToShellfire()
  shellfirebox.sendLogToShellfireAsync()
  
  luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shellfirebox"))
end

function toggleAdvancedMode()
  shellfirebox.toggleAdvancedMode()
  
  luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shellfirebox"))
end

function toggleLanguage()
  shellfirebox.toggleLanguage()
  
  luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shellfirebox"))
end

local dispatcher = require "luci.dispatcher"
