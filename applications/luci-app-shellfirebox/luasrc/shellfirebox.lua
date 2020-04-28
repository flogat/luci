local luci  = {}
local math = require "math"
local socket = require "socket"
local io = require("io")
local http = require "socket.http"
local https = require "ssl.https"
local coroutine = require "coroutine"
local table = require "table"
local ltn12 = require("ltn12")
local debugger = require "luci.debugger"
local sys = require "luci.sys"
luci.sys    = require "luci.sys"
local testfullps = luci.sys.exec("ps --help 2>&1 | grep BusyBox") --check which ps do we have
local psstring = (string.len(testfullps)>0) and  "ps w" or  "ps axfw" --set command we use to get pid
local os = require("os")
local shellfireboxTheme = "/luci-static/shellfirebox"
local bootstrapTheme = "/luci-static/bootstrap"
luci.util   =  require "luci.util"
local uci = require "luci.model.uci".cursor()
local json = require "luci.json"
local fs = require "luci.fs"
local string = require "string"
local configname = "shellfirebox"
local countrytable = require "luci.shellfirebox.countrytable"
local i18n = require "luci.i18n"
local hardwareType = 0

local tonumber, ipairs, pairs, pcall, type, next, setmetatable, require, select, tostring =
  tonumber, ipairs, pairs, pcall, type, next, setmetatable, require, select, tostring

--- Shellfire Box library.
module "luci.shellfirebox"

function getServerList()
  local serverlist = {}
  uci:foreach(configname, "server",
    function(section)
      serverlist[section.vpnServerId] = section
    end
  )

  if serverlist == nil then

    refreshServerList()
    uci:foreach(configname, "server",
      function(section)
        serverlist[section.vpnServerId] = section
      end
    )

  end

  return serverlist
end

function refreshOpenVpnParamsIfRequired()
  debugger.log("refreshOpenVpnParamsIfRequired() - start")

  uci:load(configname)
  local name = uci:get_first(configname, "openvpnparams")

  debugger.log("loaded name from config: " .. tostring(name))

  local numTries = 0
  while name == nil do
    debugger.log("name == nil, calling refreshOpenVpnParams()")
    local result, message = refreshOpenVpnParams()

    uci:load(configname)
    name = uci:get_first(configname, "openvpnparams")

    if result == false or name == nil then
      debugger.log("refreshOpenVpnParamsIfRequired() - could not refreshparams. Sleeping 10 seconds and trying again. " .. numTries)
      luci.sys.exec("sleep 10")
      numTries = numTries + 1
    end
  end

  debugger.log("refreshOpenVpnParamsIfRequired() - finish")
end

function getConnectionMode()
  return getGeneralConfigElement("connectionMode")
end

-- Set the connectionmode
-- 0 = Wireguard, 1 = UDP; 2=TCP; 3=obfsproxy over TCP
function setConnectionMode(connectionMode, reconnect)
  debugger.log("setConnectionMode("..connectionMode..") - start")

  local oldConnectionMode = getConnectionMode()

  if oldConnectionmode ~= connectionMode then

    -- if already connected (connecting...), disconnect now, make the configuration change, then reconnect.
    local reconnect = false
    local currentConnectionState = getConnectionState()
    debugger.log("currentConnectionState=" .. currentConnectionState)

    setConnectionState("connectionModeChange")
    setBlockConnectionStateUpdate(true)

    if currentConnectionState ~= "processDisconnected" then
      disconnect(true)
    end

    local name = getGeneralSectionName()
    uci:set(configname, name, "connectionMode", connectionMode)
    uci:save(configname)
    uci:commit(configname)

    if currentConnectionState == "succesfulConnect" then
      debugger.log("setConnectionMode("..connectionMode..") - already connected - enabling automatic reconnect")
      reconnect = true
    elseif currentConnectionState == "processConnecting" then 
      debugger.log("setConnectionMode("..connectionMode..") - already connecting - enabling automatic reconnect and aborting connection attempt")
      abortConnect()
      reconnect = true
    else
      debugger.log("setConnectionMode("..connectionMode..") - not connected, not connecting - not enabling automatic reconnect")
    end

    -- change protocol if required (protocol can only be changed while not connected to vpn)
    ensureCorrectProtocolForConnectionMode()

    if connectionMode == "3" then
      debugger.log("changing to obfsproxy mode, updating shared secret!")
      refreshObfsProxyData()
    end

    if connectionMode == "0" then
      debugger.log("changing to wireguard, updating server public key and own internal-ip")
      ensureWireguardKeySetup()
    end

    if reconnect then

      debugger.log("setConnectionMode("..connectionMode..") - automatic reconnect is enabled - performing connect")
      connect()
    else
      setBlockConnectionStateUpdate(false)
      setConnectionState("processDisconnected")
    end

  else
    debugger.log("connection mode not changed - doing nothing")
  end

  debugger.log("setConnectionMode("..connectionMode..") - finished")
end

function ensureWireguardKeySetup()
  debugger.log("ensureWireguardKeySetup() - start")

  if fs.isfile("/etc/keys-wireguard.crt") ~= true or fs.isfile("/etc/keys-wireguard.key") ~= true then
    debugger.log("either wireguard.crt or .key missing, generating")
    generateWireguardKeys()
  else
    debugger.log("wireguard.crt and .key exist, everything seems fine")
  end
  
  debugger.log("ensureWireguardKeySetup() - stop")
end

function sendWireguardPublicKeyToShellfire()
  debugger.log("sendWireguardPublicKeyToShellfire() - start")

  local vpn = getVpn()
  local publicKey = getWireguardPublicKeyClient()
  -- call api to set public key on the backend
  local result, message = api.call("setWireguardPublicKeyUser", {wireguardPublicKeyUser = publicKey})

  if result == true then
    debugger.log("sendWireguardPublicKeyToShellfire - succesfully sent key via api, refreshing Vpn because internal IP changed..")
    refreshVpn()

  else
    debugger.log("sendWireguardPublicKeyToShellfire() - error: could not update public key on the backend!")
  end

  debugger.log("sendWireguardPublicKeyToShellfire() - end")
end

function generateWireguardKeys()
  debugger.log("generateWireguardKeys() - start")

  luci.sys.exec("wg genkey | tee /etc/keys-wireguard.key | wg pubkey > /etc/keys-wireguard.crt")
  sendWireguardPublicKeyToShellfire()

  debugger.log("generateWireguardKeys() - end")
end

function getWireguardPublicKeyClient()
  debugger.log("getWireguardPublicKeyClient() - start")

  local publicKey = fs.readfile("/etc/keys-wireguard.crt")

  debugger.log("getWireguardPublicKeyClient() - returning publicKey=" .. tostring(publicKey))
  return publicKey
end

function getWireguardPrivateKeyClient()
  debugger.log("getWireguardPrivateKeyClient() - start")

  ensureWireguardKeySetup()

  local privateKey = fs.readfile("/etc/keys-wireguard.key")

  return privateKey
end


function getObfsProxyPort()
  return getGeneralConfigElement("ObfsProxyPort")
end

function getObfsProxySharedSecret()
  return getGeneralConfigElement("ObfsProxySharedSecret")
end

function getObfsProxyServerId()
  return getGeneralConfigElement("ObfsProxySharedServerId")
end

function setObfsProxyData(obfsProxyData)
  debugger.log("setObfsProxyData() - start")
  debugger.log(obfsProxyData)

  local name = getGeneralSectionName()
  uci:set(configname, name, "ObfsProxyServerId", obfsProxyData.ServerId)
  uci:set(configname, name, "ObfsProxyPort", obfsProxyData.Port)
  uci:set(configname, name, "ObfsProxySharedSecret", obfsProxyData.SharedSecret)
  uci:save(configname)
  uci:commit(configname)

  debugger.log("setObfsProxyData() - finished")
end

function refreshObfsProxyDataIfRequired()
  debugger.log("refreshObfsProxyDataIfRequired() - start")

  local connectionMode = getConnectionMode()
  debugger.log("retrieved connectionMode: ".. tostring(connectionMode))
  if connectionMode == "3" then
    debugger.log("connectionMode == 3, checking if we already have the obfsProxyData for the current server")

    local vpn = getVpn()
    local obfsProxyServerId = getObfsProxyServerId()

    if vpn.iServerId ~= obfsProxyServerId then
      debugger.log("refreshObfsProxyDataIfRequired() - either no ObfsProxydata yet loaded, or connecting to another server - refreshing!")
      refreshObfsProxyData()
    else
      debugger.log("refreshObfsProxyDataIfRequired() - already have the obfsproxy data for the requested server, no refresh required")
    end

  else
    debugger.log("connectionMode != 3 - refreshObfsData not required")
  end

  debugger.log("refreshObfsProxyDataIfRequired() - finish")
end

function refreshObfsProxyData()
  debugger.log("refreshObfsProxyData() - start")

  -- call api to set protocol on the backend
  local result, message = api.call("getObfsProxyData")
  if result then
    setObfsProxyData(result)
  else
    debugger.log("refreshObfsProxyData() - error: could not get shared secret from API")
  end

  debugger.log("refreshObfsProxyData() - finished")
end

function abortSendLog()
  proc.killAll(" | grep lua | grep sendLogToShellfire")

  debugger.log("abortSendLog() - finished")
end

function sendLogToShellfireAsync()
  abortSendLog()
  local cmd = "/usr/lib/lua/luci/shellfirebox/sendLogToShellfire.lua &"
  sys.call(cmd)
end

function sendLogToShellfire()
  setFrontEndMessage(i18n.translate("Uploading log..."))
  local log_content = ""

  for i=8,0,-1 do
    local filename
    if i > 0 then
      filename = "/tmp/syslog.log." .. tostring(i)
    else
      filename = "/tmp/syslog.log"
    end

    if fs.isfile(filename) then
      log_content = log_content .. "\r\n\r\n\r\n+++++++++++++++++++++++++++++++++++++++++++++++++\r\n+++++++++++++ CONTENT FROM " .. filename .. " ++++++++++++++\r\n\r\n"
      log_content = log_content .. fs.readfile(filename)
    end
  end

  log_content = base64.enc(log_content)
  local result, message = api.call("sendLog", {log = log_content})

  if result == true then
    setFrontEndMessage(i18n.translate("Log succesfully sent to Shellfire"))
    luci.sys.exec("sleep 15")
    setFrontEndMessage("")
  else
    setFrontEndMessage(i18n.translate("Could not send log, message code:").. " " .. tostring(message))
  end

  luci.sys.exec("sleep 15")
  setFrontEndMessage("")
end

-- refresh the openvpn params for this box (changes with the selected server and protocol)
-- @return true if the refresh was succesful, false otherwise
function refreshOpenVpnParams()

  local newvpnparams, message = api.call("getOpenVpnParams")

  if newvpnparams ~= false then
    debugger.log("successfully retrieved new openvpnparams")
    debugger.log(newvpnparams)
    -- delete all servers from uci config file
    uci:delete_all(configname, "openvpnparams")

    uci:save(configname)
    uci:commit(configname)

    local localparams = {}
    for k, v in pairs(newvpnparams) do
      cleankey = string.gsub(k, "-", "_")
      localparams[cleankey] = v
    end

    uci:section(configname, "openvpnparams", nil, localparams)

    uci:save(configname)
    uci:commit(configname)
    return true
  else
    debugger.log("refreshOpenVpnParams() failed with message: " .. message)
    return false, message
  end
end

function abortConnect()
  local level = 15

  local connectionMode = tostring(getConnectionMode())
  if connectionMode == "0" then
    level = 1
  end

  proc.killAll(" | grep lua | grep connect", level)
  setBlockConnectionStateUpdate(false)
  setConnectionState("processDisconnected")
  debugger.log("abortConnect() - finished")
end


function connectAsync()
  abortConnect()
  local cmd = "/usr/lib/lua/luci/shellfirebox/connect.lua &"
  debugger.log("connectAsync")
  debugger.log(cmd)
  sys.call(cmd)
end

function setServerToAsync(serverid)
  abortSetServer()
  local cmd = "/usr/lib/lua/luci/shellfirebox/setServerTo.lua " .. tostring(serverid) ..  " &"
  debugger.log("setServerToAsync(" .. tostring(serverid) .. ") - invoking cmd: " .. cmd)
  sys.call(cmd)
end

function setConnectionModeAsync(serverid)
  abortSetConnectionMode()
  local cmd = "/usr/lib/lua/luci/shellfirebox/setConnectionMode.lua " .. tostring(serverid) ..  " &"
  debugger.log("setConnectionModeAsync(" .. tostring(serverid) .. ") - invoking cmd: " .. cmd)
  sys.call(cmd)
end

-- selects a server on the backend - needs a refreshVpn afterwards
-- @return true if the refresh was succesful, false otherwise
function setServerTo(section)
  debugger.log("setServerTo() - start")

  local currentConnectionState = getConnectionState()

  setConnectionState("serverChange")
  setBlockConnectionStateUpdate(true)

  disconnect(true)
  luci.sys.exec("sleep 1")

  local reconnect = false
  if currentConnectionState == "succesfulConnect" or currentConnectionState == "processConnecting"
  then
    debugger.log("setServerTo() - was already connected, reconnecting later. currentConnectionState = " .. currentConnectionState)
    reconnect = true
  else
    debugger.log("setServerTo() - was not already connected, not reconnecting later. currentConnectionState = " .. currentConnectionState)

  end

  local serverid
  if type(section) == "table" then
    uci:load(configname)
    serverid = uci:get(configname, section, "vpnServerId")
  else
    serverid = section
  end

  local success, message = api.call("setServerTo", {vpnServerId = serverid})

  refreshServerList()
  refreshWebServiceAliasList()
  refreshVpn()

  local connectionMode = tostring(getConnectionMode())
  -- perform openVpn refresh stuff only when in openVpn connection mode
  if (connectionMode ~= "0") then
    refreshOpenVpnParams()
    refreshCertificatesIfRequired()
    refreshObfsProxyDataIfRequired()
  end

  if reconnect then
    debugger.log("setServerTo() - was connected before, reconnecting now")
    connect()
  else
    setBlockConnectionStateUpdate(false)
    setConnectionState("processDisconnected")
  end

  debugger.log("setServerTo() - finished")
  return success, message

end

-- refresh the shellfire vpn product details for this box
-- @return true if the refresh was succesful, false otherwise
function refreshVpn()

  local newvpndetails, message = api.call("getVpn")

  if newvpndetails ~= false then
    -- delete all servers from uci config file
    uci:delete_all(configname, "vpn")
    uci:save(configname)
    uci:commit(configname)

    uci:section(configname, "vpn", nil, newvpndetails)

    uci:save(configname)
    uci:commit(configname)
    return true
  else
    return false, message
  end
end

function getVpn()
  uci:load(configname)
  local name = uci:get_first(configname, "vpn")
  if name == nil then
    refreshVpn()
    name = uci:get_first(configname, "vpn")
  end

  if name ~= nil then
    return uci:get_all(configname, name)
  else
    return nil
  end
end

function refreshCertificatesIfRequired()
  local req = false
  if fs.isdirectory("/etc/keys/") == false then
    req = true
  else
    local keyDirContentTable = fs.dir("/etc/keys")

    if #keyDirContentTable <= 2 then
      req = true
    else
      local vpn = getVpn()
      local vpnId = vpn.iVpnId
      if not fs.isfile("/etc/keys/sf" .. vpnId .. ".crt") then
        req = true
      end
    end

  end



  if req then
    refreshCertificates()
  end

end

-- refresh the certificates for this box from the server. should only be required for the initial setup or in case of reset.
-- @return true if the refresh was succesful, false otherwise
function refreshCertificates()

  local certs, message = api.call("getCertificates")

  if certs ~= false then

    local keydir = "/etc/keys/"

    if fs.isdirectory("/etc/keys/") == false then
      fs.mkdir(keydir)
    end

    for filename, filecontent in pairs(certs) do
      fs.writefile(keydir .. filename, filecontent)
    end
    return true
  else
    debugger.log("refreshCertificates() error: could not refresh certificates. message: " .. tostring(message))
    return false, message
  end
end

function getSectionName(cnfg, sctn)
  uci:load(cnfg)
  local name = uci:get_first(cnfg, sctn)
  if name == nil then
    uci:section(cnfg, sctn)
    name = uci:get_first(cnfg, sctn)
  end

  return name
end

function getGeneralSectionName()
  return getSectionName(configname, "general")
end

function getUid()
  local uid = fs.readfile("/etc/sfboxuid")
  uid = luci.util.trim(uid)

  if uid == nil or uid == "" then
    debugger.log("getUid() - warning: could not read Uid file or is empty")
  end

  return tostring(uid)
end

function getSingleConfigElement(confname, cat, element)
  uci:load(confname)
  local result = uci:get_first(confname, cat, element)
  return result
end

function getGeneralConfigElement(element)
  return getSingleConfigElement(configname, "general", element)
end

function setSingleConfigElement(cnfg, sctn, element, value)
  local name = getSectionName(cnfg, sctn)
  uci:set(cnfg, name, element, value)
  uci:save(cnfg)
  local result = uci:commit(cnfg)

  if not result then
    debugger.log("setSingleConfigElement - ERROR: could not write to UCI!")
  end
end

function setGeneralConfigElement(element, value)
  setSingleConfigElement(configname, "general", element, value)
end

function getFrontEndMessage()
  return getGeneralConfigElement("frontEndMessage")
end

function setFrontEndMessage(msg)
  setGeneralConfigElement("frontEndMessage", msg)
end

function markWebServiceAliasAsBad(aliasId)
  local dontRestartAsyncMeasure = false
  if aliasId == nil then
    aliasId = getGeneralConfigElement("webserviceAliasId")
    dontRestartAsyncMeasure = true
  end

  local alias = getWebServiceAliasById(aliasId)
  local name = getUciNameForWebServiceAliasById(aliasId)
  uci:set(configname, name, "ping", 10000000)
  uci:save(configname)
  uci:commit(configname)

  setBestWebServiceAlias(dontRestartAsyncMeasure)
end

function getWebServiceEndpoint(aliasId)
  if aliasId == nil then
    aliasId = getGeneralConfigElement("webserviceAliasId")
  end

  if aliasId == nil then aliasId = 10 end
  if tonumber(aliasId) == 0 then aliasId = 10 end
  debugger.log(aliasId)

  local alias = getWebServiceAliasById(aliasId)
  if alias == nil then
    return "https://www.shellfire.de/webservice/json.php?action="
  else
    return "https://" .. alias.host .. ":" .. alias.port .. "/webservice/json.php?action="
  end
end

led =  {}

function led.handleUpdatedConnectionState(state)
    if state == "processConnecting" or state == "connectionModeChange" or state == "processRestarting"  or state == "serverChange" then
      led.blinkAsync()
    elseif state == "succesfulConnect" then
      led.on()
    elseif state == "processDisconnected" then
      led.off()
    else
      led.off()
    end
end

function led.on()
  if not led.hasLed() then
    return
  end

  led.abortBlink()
  led.sysOn()
end

function led.getHardwareType()
  if hardwareType == 0 then
    local path = led.getPath()
    if string.match(path, "wt3020") then
      hardwareType = "wt3020"
    else
      hardwareType = "minibox"
    end

  end

  return hardwareType
end

function led.getValueOn()
  local type = led.getHardwareType()
  if hardwareType == "wt3020" then return "0" else return "1" end
end

function led.getValueOff()
  local type = led.getHardwareType()
  if hardwareType == "wt3020" then return "1" else return "0" end
end

function led.sysOn()
  local path = led.getPath()
  luci.sys.call("echo " .. led.getValueOn()  .. " > " .. path)
end

function led.sysOff()
  local path = led.getPath()
  luci.sys.call("echo " .. led.getValueOff()  .. " > " .. path)
end

function led.off()
  if not led.hasLed() then
    return
  end

  led.abortBlink()
  led.sysOff()
end

function led.blinkAsync()
  -- avoid duplicate execution
  led.abortBlink()
  local cmd = "/usr/lib/lua/luci/shellfirebox/ledblink.lua &"
  debugger.log(cmd)
  sys.call(cmd)
end

-- should be called asynchronosly only because this blocks
function led.blink()
  if not led.hasLed() then
    return
  end

  while true do
    led.sysOn()
    socket.sleep(0.5)
    led.sysOff()
    socket.sleep(0.5)
  end
end

-- should be called asynchronosly only because this blocks
function led.blinkfast()
  if not led.hasLed() then
    return
  end

  while true do
    led.sysOn()
    socket.sleep(0.1)
    led.sysOff()
    socket.sleep(0.1)
  end
end

function led.abortBlink()
  proc.killAll(" | grep lua | grep ledblink")
end

function led.hasLed()
  local path = led.getPath()

  local result = fs.isfile(path)

  return result
end

function led.getPath()
  local path1 = "/sys/class/leds/wt3020:blue:power/brightness"
  local path2 = "/sys/class/leds/minibox_v3:green:system/brightness"

  if fs.isfile(path1) then
    return path1
  elseif fs.isfile(path2) then
    return path2
  else 
    return ""
  end
end


api = {}
-- Call the Shellfire Json API and return parsed object
function api.call(action, params, aliasId)

  local uid = getUid()

  local url = getWebServiceEndpoint(aliasId) .. action
  --local url = "http://uat.shellfire.remote.de/webservice/json.php?action=" .. action
  debugger.log(url)
  local requestbody = json.encode(params)

  local headers = {
    ["Content-Type"]            = "application/json";
    ["X-Authorization-Token"]   = uid;
    ["Content-Length"] = tostring(#requestbody)
  }
  debugger.log("X-Authorization-Token = " .. uid)

  if params ~= nil and not action == "sendLog" then
    debugger.log("api.call - params [---------]")
    debugger.log(params)
    debugger.log("[---------] api.call - params")
  end

  local responsebody = {}

  http.TIMEOUT = 10
  local a,b,c=https.request{
    url = url,
    method = "POST",
    headers = headers,
    source = ltn12.source.string(requestbody),
    sink = ltn12.sink.table(responsebody)
  }

  local result = ""
  if b == 200 then

    for i, k in pairs(responsebody) do
      result = result .. k
    end

    debugger.log("api.call - result [---------]")
    debugger.log(result)
    debugger.log("[---------] api.call - result")

    jsonresult = json.decode(result)
    if jsonresult.status == "success" then
      return jsonresult.data or true
    else
      return false, jsonresult.message
    end

  else
    debugger.log("api.call - error [---------]")
    debugger.log(a)
    debugger.log(b)
    debugger.log(c)
    debugger.log("[---------] api.call - error")

    if b == nil or b == "timeout" or b == 404 or b == 500 or b == "connection refused" then
      debugger.log("i detected that the following error occured so i mark this endpoint as bad: " .. (b or ""))
      markWebServiceAliasAsBad(aliasId)

      -- in case aliasId is set, this was a call possibly specific to test a given endpoint - so do not retry
      if aliasId == nil then
        debugger.log("api.call - aliasId not set, retrying with other alias")
        return api.call(action, params)
      else
        debugger.log("api.call - aliasId WAS set, not retrying")
      end
    else
      debugger.log("an error occured while calling the api - maybe no internet connection available? msg: " .. tostring(b))
      return false, b
    end
  end
end

function abortSetServer()
  proc.killAll(" | grep lua | grep setServerTo")
end

function abortSetConnectionMode()
  proc.killAll("| grep lua | grep setConnectionMode")
  debugger.log("abortSetConnectionMode() - finished")
end


function disconnect(noStateUpdate)
  debugger.log("disconnect("..tostring(noStateUpdate)..") - start")

  setAutostartRequested("false")

  local connectionMode = tostring(getConnectionMode())

  if connectionMode == "0" then
    disconnectWireguard()
  else
    disconnectOpenVpn()
  end

  if noStateUpdate ~= true then
    setConnectionState("processDisconnected")
  end

  debugger.log("disconnect() - finished")
end

function disconnectOpenVpn()
  debugger.log("disconnectOpenVpn() - start")

  proc.killAll(" | grep openvpn | grep -v openvpnparser")
  proc.killAll(" | grep obfsproxy")

  debugger.log("disconnectOpenVpn() - finished")
end

function isWireguardInterfaceUp()
  debugger.log("isWireguardInterfaceUp() - start")

  local handle = io.popen("ifstatus wg0")
  local ifstatus = handle:read("*a")
  handle:close()

  local interfaceIsUp

  if ifstatus == "Interface wg not found" then
    debugger.log("isWireguardInterfaceUp() - wg0 interface not found, returning false")
    interfaceIsUp = false
  else
    local jsonresult = json.decode(ifstatus)
debugger.log(jsonresult.up)
    if jsonresult.up == true then
      interfaceIsUp = true
    else
      interfaceIsUp = false
    end
  end

  debugger.log("isWireguardInterfaceUp() - finished - returning status=" .. tostring(interfaceIsUp))
  return interfaceIsUp
end


function disconnectWireguard()
  debugger.log("disconnectWireguard() - start")

  local wireguardInterfaceIsUp = isWireguardInterfaceUp()
debugger.log(wireguardInterfaceIsUp)
  if wireguardInterfaceIsUp == true then
    debugger.log("disconnectWireguard() - wg0 interface is up, performing disconnect command")
    luci.sys.exec("ifdown wg0 && ifdown wan && ifup wan")
  else
    debugger.log("disconnectWireguard() - wg0 interface is down, not performing disconnect command")
  end

  debugger.log("disconnectWireguard() - finished")
end

function getProtocol()
  return getSingleConfigElement(configname, "openvpnparams", "proto")
end

function setProtocol(protocol)
  debugger.log("setProtocol("..protocol..") - start")

  -- call api to set protocol on the backend
  local result, message = api.call("setProtocol", {proto = protocol})

  if result == true then
    debugger.log("setProtocol - succesfully changed via api, now refreshing vpn and openVpnParams..")
    refreshVpn()
    refreshOpenVpnParams()

  else
    debugger.log("setProtocol() - error: could not change protocol on the backend!")
  end


  debugger.log("setProtocol("..protocol..") - finished")
end

function ensureCorrectProtocolForConnectionMode()
  debugger.log("ensureCorrectProtocolForConnectionMode() - start")

  -- make sure we have the right protocol for the specified connection mode
  local currentConnectionMode = getConnectionMode()
  local currentProtocol = getProtocol()
  if currentConnectionMode == nil then
    currentConnectionMode = "unknown"
  end

  if currentProtocol == nil then
    currentProtocol = "udp"
  end

  debugger.log("ensureCorrectProtocolForConnectionMode() - currentConnectionMode: " .. currentConnectionMode)
  debugger.log("ensureCorrectProtocolForConnectionMode() - currentProtocol: " .. currentProtocol)

  local vpnProto = getSingleConfigElement(configname, "vpn","eProtocol")

  if vpnProto == nil then
    debugger.log("ensureCorrectProtocolForCOnnectionMode() - vpn's proto is nil, setting to udp")
    setProtocol("udp")
  end

  if currentConnectionMode == "1" and currentProtocol ~= "udp" then
    debugger.log("ensureCorrectProtocolForConnectionMode() - connectionmode 1 requires UDP, changing protocol to udp")
    setProtocol("udp")
  elseif (currentConnectionMode == "2" or currentConnectionMode == "3") and currentProtocol ~= "tcp" then
    debugger.log("ensureCorrectProtocolForConnectionMode() - connectionmode 2 and 3 require TCP, changing protocol to TCP")
    setProtocol("tcp")
  else
    debugger.log("ensureCorrectProtocolForConnectionMode() - no change in connection mode required")
  end

  debugger.log("ensureCorrectProtocolForConnectionMode() - end")
end

function getFirewallZoneByName(zone)
  local localZone = nil

  uci:foreach("firewall", "zone", function(s) 
    
    if s["name"] == zone then
      localZone = s[".name"]
    end

  end)

  return localZone
end

function getFirewallZoneWan()
  local name = getFirewallZoneByName("wan")
  debugger.log("retrieved firewall zone wan name: " .. name)

  return name
end

function restartFirewall()
  debugger.log("restartFirewall() - start")
  luci.sys.exec("/etc/init.d/firewall restart")  
  debugger.log("restartFirewall() - finished")
end

function setConfigElement(cnfg, name, element, value)
  uci:set(cnfg, name, element, value)
  uci:save(cnfg)                   
  local result = uci:commit(cnfg)
                                               
  if not result then
    debugger.log("setConfigElement - ERROR: could not write to UCI!")
  end
end

function getConfigElement(confname, cat, element)    
  uci:load(confname)      
  local result = uci:get(confname, cat, element)                              
  return result         
end    

function deleteForwarding(dest)
  debugger.log("deleteForwarding to : " .. tostring(dest))
    uci:delete_all("firewall", "forwarding", 
        function(section)
          debugger.log("comparator called for section:")
          
          local result =  dest == nil or section["dest"] == dest
          debugger.log("comparator returning result: " .. tostring(result))
          return result
        end
    )
                          
    uci:save("firewall")  
    uci:commit("firewall")
end

function addForwarding(dest)
  local section = uci:add("firewall", "forwarding")
  uci:set("firewall", section, "src", "lan")
  uci:set("firewall", section, "dest", dest)
  uci:save("firewall")
  uci:commit("firewall")
end


function enableKillswitch()
  debugger.log("enableKillswitch() - start")
  local section = getFirewallZoneWan()
  debugger.log("retrieved section name: " .. section)
  local masq = getConfigElement("firewall", section, "masq")
  debugger.log("retrieved current value of masq: " .. masq)
  if masq == "0" then
    debugger.log("no need to enable killswitch, already firewall.zone[wan].masq==0")
  else
    setConfigElement("firewall", section, "masq", "0")
    deleteForwarding("wan")

    restartFirewall()
  end

  debugger.log("enableKillswitch() - stop")
end

function disableKillswitch()
  debugger.log("disableKillswitch() - start")

  local section = getFirewallZoneWan()
                        
  local masq = getConfigElement("firewall", section, "masq")
  debugger.log("retrieved current value of masq: " .. tostring(masq))
  if masq == "1" then
    debugger.log("no need to disable killswitch, already firewall.zone[wan].masq==1")
  else 
    setConfigElement("firewall", section, "masq", "1")
    addForwarding("wan")
    restartFirewall()
  end                      

  debugger.log("disableKillswitch() - stop")
end

-- connects to the vpn / starts openvpn
function connect()
  debugger.log("shellfirebox.connect() - start")
  
  -- avoid duplicate openvpn instances
  disconnect(true)
  
  setAutostartRequested(true)
  setConnectionState("processConnecting")

  getVpn()


  local connectionMode = tostring(getConnectionMode())
  if connectionMode == "0" then
    connectWireguard()
  else
    connectOpenVpn()
  end
  debugger.log("shellfirebox.connect() - end")
end

function connectWireguard()
  debugger.log("shellfirebox.connectWireguard() - start")
  
  proc.killAll(" | grep wireguardstatemonitor")

  local server = getSelectedServerDetails()
  local wireguardPublicKeyServer = server.wireguardPublicKey

  local wireguardPublicKeyServer = server.wireguardPublicKey
  local wireguardPrivateKeyClient = getWireguardPrivateKeyClient()

  local vpn = getVpn()
  if vpn.iProductTypeId ~= 11 then
    sendWireguardPublicKeyToShellfire()
    vpn = getVpn()
  end


  local internalIP = vpn.sWireguardIP
  local serverHost = vpn.sListenHost

  luci.sys.exec("uci set network.@wireguard_wg0[0].public_key=" .. tostring(wireguardPublicKeyServer))
  luci.sys.exec("uci set network.@wireguard_wg0[0].endpoint_host=" .. serverHost)
  luci.sys.exec("uci set network.wg0.private_key=" .. wireguardPrivateKeyClient)
  luci.sys.exec("uci set network.wg0.addresses=" .. internalIP)
  luci.sys.exec("uci commit")

  luci.sys.exec("ifup wg0")

  luci.sys.exec("/usr/lib/lua/luci/shellfirebox/wireguardstatemonitor.lua &")

  debugger.log("shellfirebox.connectWireguard() - finish")
end

function connectOpenVpn()
  debugger.log("shellfirebox.connectOpenVpn() - start")
 
  local connectionMode = tostring(getConnectionMode())
  refreshOpenVpnParamsIfRequired()
  refreshCertificatesIfRequired()

  ensureCorrectProtocolForConnectionMode()
  
  
  local server = getSingleConfigElement(configname, "vpn","iServerId")
  local proto = getSingleConfigElement(configname, "vpn","eProtocol")
  local obfsProxyYesNo = connectionMode == "3" and "yes" or "no"
  debugger.log("Connecting to Server " .. tostring(server) .. " with proto " .. tostring(proto) .. " and obfsProxy: " .. tostring(obfsProxyYesNo))
  
  
  local obfsProxyPort
  if connectionMode == "3" then
    refreshObfsProxyDataIfRequired()
    obfsProxyPort = getObfsProxyPort()
  end

  local remoteHost = ""

  -- assemble start params
  uci:load(configname)
  local name = uci:get_first(configname, "openvpnparams")

  local allparams = ""
  uci:foreach(configname, "openvpnparams",
    function(s)
      for k, v in pairs(s) do
        if string.sub(k,1,1) ~= "." and string.sub(k, 1,8) ~= "service" then  -- ignore the meta stuff
          local cleank = string.gsub(k, "_", "-")
          if v == "is-flag" then
            allparams = allparams .. "--" .. tostring(cleank) .. " "
          else
            -- adjustments for obfsproxy
            if connectionMode == "3" and cleank == "remote" then
              -- replace the port with obfsProxyPort
              debugger.log("adjustments for obfs proxy - old: " .. tostring(cleank) .. " => " .. tostring(v))
              local parts = luci.util.split( v, " " )
              remoteHost = parts[1]
              v = parts[1] .. " " .. tostring(obfsProxyPort)
              debugger.log("adjustments for obfs proxy - new: " .. tostring(cleank) .. " => " .. tostring(v))
            end
            allparams = allparams .. "--" .. tostring(cleank) .. " " .. tostring(v) .. " "
          end
        end
      end
    end
  )

  debugger.log("succesfully compiled all parameters - making further adjustments for up/down scripts")
  allparams = allparams .. " --script-security 2 --route-up /usr/lib/lua/luci/shellfirebox/scripts/up.sh --route-pre-down /usr/lib/lua/luci/shellfirebox/scripts/down.sh"
  allparams = allparams .. " --route 10.0.0.0 255.0.0.0 net_gateway --route 172.16.0.0 255.240.0.0 net_gateway --route 192.168.0.0 255.255.0.0 net_gateway"

  debugger.log("parameters finalised.")

  -- some more adjustments for obfsproxy
  if connectionMode == "3" then
    debugger.log("connectionMode  is 3 - starting obfs proxy")
    math.randomseed(os.time())
    local obfsProxyLocalPort = math.random(20000, 30000)
    debugger.log("starting obfsproxy connection on local port: " .. obfsProxyLocalPort)

    local obfsProxySharedSecret = getObfsProxySharedSecret()
    local obfsproxystart = "/usr/bin/obfsproxy --log-file=/tmp/syslog.log --log-min-severity=info --no-safe-logging "
    obfsproxystart  = obfsproxystart .. "obfs2 --shared-secret=" .. obfsProxySharedSecret .. " socks 0.0.0.0:" .. obfsProxyLocalPort .. " &"
    debugger.log(obfsproxystart)
    luci.sys.call(obfsproxystart)

    local paramsToAdd = " --route " .. remoteHost .. " 255.255.255.255 net_gateway"
    paramsToAdd = paramsToAdd .. " --connect-retry-max 1 --socks-proxy 127.0.0.1 " .. obfsProxyLocalPort

    debugger.log("adding params to openvpn start command: " .. paramsToAdd)
    allparams = allparams .. paramsToAdd

  end

  local openvpnstart = "/usr/sbin/openvpn " .. allparams .. " | /usr/lib/lua/luci/shellfirebox/openvpnparser.lua &"
  
  debugger.log("start the openvpn")
  debugger.log(openvpnstart)
  luci.sys.call(openvpnstart)

  debugger.log("shellfirebox.connectOpenVpn() - end")
end



function getWebServiceAliasById(aliasId)
  local result
  uci:foreach(configname, "webservicealias",
    function(alias)
      if tonumber(alias.aliasId) == tonumber(aliasId) then
        result = alias
      end
    end
  )

  if result == nil then
    debugger.log("getWebServiceAliasById(" .. tostring(aliasId) .. ") - error: returning nil")
  end

  return result

end


function getServerById(serverId)
  local result
  uci:foreach(configname, "server",
    function(server)
      if server.vpnServerId == serverId then
        result = server
      end
    end
  )

  if result == nil then
    debugger.log("getServerById(" .. tostring(serverId) .. ") - warning: returning nl. probably out of date serverlist - triggering reload...")
    refreshServerList()

    uci:foreach(configname, "server",
      function(server)
        if server.vpnServerId == serverId then
          result = server
        end
      end
    )
    if result == nil then
      debugger.log("after reload of serverlist, result still nil")
    else
      debugger.log("reload of serverlist worked, result not nil anymore")
    end
  end

  return result
end

function getSelectedServerDetails()
  local result = nil

  local vpn = getVpn()
  if vpn ~= nil then
    local selectedServerId = vpn.iServerId

    result = getServerById(selectedServerId)
  end

  if vpn == nil then
    debugger.log("getSelectedServerDetails - warning: could not get vpn, it is nil")
  end

  if result == nil then
    debugger.log("getSelectedServerDetails - warning: selected server is nil")
  end

  return result
end

function getAutostartRequested()
  local startRequested = getGeneralConfigElement("autostartRequested")
  return startRequested
end

function setAutostartRequested(startRequested)
  setGeneralConfigElement("autostartRequested", tostring(startRequested))
end

function getConnectionState()
  return getGeneralConfigElement("connectionstate")
end

function setConnectionState(state, parsedResult)
  debugger.log("setConnectionState("..tostring(state)..", " .. tostring(parsedResult) .. ") - start")

  local currentState = getConnectionState()
  if state == "failedPassPhrase" or state == "certificateInvalid" then
    refreshOpenVpnParams()
    refreshVpn()
    refreshCertificates()
    connect()
  end

  -- after succesful connect, info needs to be displayed to user
  if state == "succesfulConnect" or state == "generalError" or state == "connecting" then
    setBlockConnectionStateUpdate(false)
  end

  local doBlockStateUpdate = getBlockConnectionStateUpdate()
  if doBlockStateUpdate == true then
      debugger.log("setConnectionState() - connectionStateUpdates are currently blocked, not processing update")
  else
    debugger.log("setConnectionState() - connectionStateUpdates are not blocked, performing update to ".. tostring(state))
    led.handleUpdatedConnectionState(state)

    if state == "succesfulConnect" then
      webServiceAliasMeasurePerformanceAllAsync()
    end
    setGeneralConfigElement("connectionstate", state)
  end

  debugger.log("setConnectionState("..state..") - finished")
end

function setBlockConnectionStateUpdate(doblock)
  local val = 0
  if doblock == true then
    val = 1
  else
    val = 0
  end
  setGeneralConfigElement("blockConnectionStateUpdate", val)
end

function getBlockConnectionStateUpdate()
  result = getGeneralConfigElement("blockConnectionStateUpdate") == "1"
  return result
end

-- update the list of possible webservice endpoints
function refreshWebServiceAliasList()
  debugger.log("refreshWebServiceAliasList() - start")

  local result = true
  local message = ""
  local newaliaslist, message = api.call("getWebServiceAliasList")
  if newaliaslist ~= false then
    -- delete all servers from uci config file
    uci:delete_all(configname, "webservicealias")

    uci:save(configname)
    uci:commit(configname)

    -- for every server
    for i, alias in pairs(newaliaslist) do
      uci:section(configname, "webservicealias", nil, alias)
    end

    uci:save(configname)
    uci:commit(configname)

    result = true
  else
    result = false
  end

  debugger.log("refreshWebServiceAliasList() - returning result, message")
  debugger.log("result")
  debugger.log(result)
  debugger.log("message")
  debugger.log(message)
  return result, message
end

function getUciNameForWebServiceAliasById(aliasId)
  debugger.log("getUciNameForWebServiceAliasById(" .. tostring(aliasId) .. ") - start")

  local result = ""
  uci:foreach(configname, "webservicealias",
    function (alias)
      if tostring(alias.aliasId) == tostring(aliasId) then
        result = alias[".name"]
      end
    end
  )

  debugger.log("getUciNameForWebServiceAliasById(" .. tostring(aliasId) .. ") - returning result")
  debugger.log(result)
  return result
end

function webServiceAliasMeasurePerformance(aliasId)
  debugger.log("webServiceAliasMeasurePerformance(" .. tostring(aliasId) .. ") - start")
  name = getUciNameForWebServiceAliasById(aliasId)
  local alias = getWebServiceAliasById(aliasId)
  uci:set(configname, name, "ping", 10000000)
  uci:save(configname)
  uci:commit(configname)
  local host = alias.host
  local port = alias.port

  debugger.log("webServiceAliasMeasurePerformance - measuring performance for host: " .. tostring(alias.host))
  local start_time = socket.gettime()*1000
  local res = api.call("getServerlist", nil, aliasId)
  local end_time = socket.gettime()*1000

  local elapsed_time = math.floor(end_time - start_time)
  if res == false then
    debugger.log("res == false")
    elapsed_time = 10000000
  end

  debugger.log("webServiceAliasMeasurePerformance - aliasId " .. tostring(alias.aliasId) .. " elapsed_time: " .. tostring(elapsed_time))
  uci:set(configname, name, "ping", elapsed_time)
  uci:save(configname)
  uci:commit(configname)

  debugger.log("webServiceAliasMeasurePerformance(" .. tostring(aliasId) .. ") - end")
end

function callWireguardDownScript()
  luci.sys.call("/usr/lib/lua/luci/shellfirebox/scripts/down-wireguard.sh")
end


function callWireguardUpScript()
  luci.sys.call("/usr/lib/lua/luci/shellfirebox/scripts/up-wireguard.sh")
end


function webServiceAliasMeasurePerformanceAll()
  debugger.log("webServiceAliasMeasurePerformanceAll() - start - sleeping 10 minutes")
  luci.sys.exec("sleep 600")
  debugger.log("webServiceAliasMeasurePerformanceAll() - slept 10 minutes without interruption, performing measurement")
  
  local buffer = {}
  local i = 0
  uci:foreach(configname, "webservicealias",
    function (alias)
      buffer[i] = alias
      i = i + 1
    end
  )

  for i, alias in pairs(buffer) do
    webServiceAliasMeasurePerformance(alias.aliasId)
  end

  debugger.log("webServiceAliasMeasurePerformanceAll() - finished measuring performance for all aliases - setting best webservice")

  setBestWebServiceAlias(true)

  debugger.log("webServiceAliasMeasurePerformanceAll() - return")
end

function setBestWebServiceAlias(dontRestartAsyncMeasure)
  debugger.log("setBestWebServiceAlias("..tostring(dontRestartAsyncMeasure)..") - start")
  local lowestId = 0
  local lowestPing = 10000000
  local ids = {}
  local i = 0
  uci:foreach(configname, "webservicealias",
    function (alias)
      local current_ping = tonumber(alias.ping)
      if current_ping == nil then current_ping = 10000000 end
      if current_ping < lowestPing then
        lowestId = alias.aliasId
        lowestPing = current_ping
      end

      ids[i] = alias.aliasId
      i = i + 1
    end
  )

  -- all not reachable - randomly select 1 and (re)start
  if lowestId == 0 and i > 0 then
    debugger.log("setBestWebServiceAlias - all were not reachable, setting a random one")
    math.randomseed(os.time())
    local rnd = math.random(i) - 1
    lowestId = ids[rnd]
    debugger.log("lowestId = ids[rnd] = ids[" .. tostring(rnd) .. "] = " .. tostring(lowestId))

    if dontRestartAsyncMeasure == nil then
      debugger.log("restarting the async measurement process")
      webServiceAliasMeasurePerformanceAllAsync()
    else
      debugger.log("NOT restarting the async measurement process")
    end
  elseif i == 0 then
    debugger.log("not a single webservicealias option available in uci")
  end

  local name = getGeneralSectionName()
  debugger.log("uci:set("..tostring(configname)..", "..tostring(name).." webserviceAliasId, "..tostring(lowestId)..")")
  uci:set(configname, name, "webserviceAliasId", lowestId)
  uci:save(configname)
  uci:commit(configname)

  debugger.log("setBestWebServiceAlias("..tostring(dontRestartAsyncMeasure)..") - end - new webserviceAliasId: " .. lowestId)
end

function webServiceAliasMeasurePerformanceAllAsync()
  abortWebServiceAliasMeasurePerformance()
  debugger.log("sys.call(/usr/lib/lua/luci/shellfirebox/refreshWebServiceAliasPing.lua &)");
  sys.call("/usr/lib/lua/luci/shellfirebox/refreshWebServiceAliasPing.lua &")
end

function abortWebServiceAliasMeasurePerformance()
  proc.killAll(" | grep lua | grep refreshWebServiceAliasPing")

  debugger.log("abortWebServiceAliasMeasurePerformance() - finished")
end


--- Retrieve information about the list of Shellfire VPN Servers
-- @return true if the refresh was succesful, false otherwise
function refreshServerList()

  local newserverlist, message = api.call("getServerlist")

  if newserverlist ~= false then
    -- delete all servers from uci config file
    uci:delete_all(configname, "server")

    uci:save(configname)
    uci:commit(configname)

    -- for every server
    for i, server in pairs(newserverlist) do
      server.iso = countrytable.getIsoCodeByCountry(server.country)

      uci:section(configname, "server", nil, server)
    end

    uci:save(configname)
    uci:commit(configname)

    return true
  else
    return false, message
  end

end

function isAdvancedMode()
  uci:load("luci")
  local currentTheme = uci:get_first("luci", "core", "mediaurlbase")

  return currentTheme == bootstrapTheme
end

function setTheme(theme)
  uci:set("luci", "main", "mediaurlbase", theme)
  uci:save("luci")
  uci:commit("luci")
end

function toggleAdvancedMode()
  if isAdvancedMode() then
    debugger.log("isAdvancedMode")
    setTheme(shellfireboxTheme)
  else
    debugger.log("is regular mode")
    setTheme(bootstrapTheme)
  end
end

function getLanguage()
  uci:load("luci")
  return uci:get_first("luci", "core", "lang")
end

function setLanguage(lang)
  uci:set("luci", "main", "lang", lang)
  uci:save("luci")
  uci:commit("luci")
end

function toggleLanguage()
  local lang = getLanguage()

  if lang == "de" then
    lang = "auto"
  else
    lang = "de"
  end

  setLanguage(lang)
end


local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
base64 = {}
-- encoding
function base64.enc(data)
  return ((data:gsub('.', function(x)
    local r,b='',x:byte()
    for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
    return r;
  end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
    if (#x < 6) then return '' end
    local c=0
    for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
    return b:sub(c+1,c+1)
  end)..({ '', '==', '=' })[#data%3+1])
end

-- decoding
function base64.dec(data)
  data = string.gsub(data, '[^'..b..'=]', '')
  return (data:gsub('.', function(x)
    if (x == '=') then return '' end
    local r,f='',(b:find(x)-1)
    for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
    return r;
  end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
    if (#x ~= 8) then return '' end
    local c=0
    for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(7-i) or 0) end
    return string.char(c)
  end))
end

proc =  {}
function proc.getPid(pattern)
  local psPattern = "%s " .. pattern .. " | grep -v grep | awk '{print $1}'"
  local pid = sys.exec(psPattern % { psstring })
  return pid
end

function proc.killAll(pattern, level)
  local pid = proc.getPid(pattern)
  level = level or 15

  if pid and pid ~= "" and #pid > 0
  then
    local pidTable = luci.util.split(pid)
    
    for i, k in pairs(pidTable) do
      if k and k ~= "" and #k > 0
      then
        sys.process.signal(k,level)
      end
    end
  end
end
