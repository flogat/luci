	local shellfirebox = require "luci.shellfirebox"
	local debugger = require "luci.debugger"
	i18n = require "luci.i18n"
	
function getAjaxFrontEndMessage()
  luci.http.prepare_content("application/json")
  local msg = shellfirebox.getFrontEndMessage()
  
  if msg == nil then msg = "" end
  
  luci.http.write_json(msg)
  return 
end	
	
function getAjaxConnectionState()
  local statecode = shellfirebox.getConnectionState()
    
    local result = {}
    
    if statecode == "processDisconnected"
    then
      result.state = "disconnected"
      result.stateText = i18n.translate("Disconnected")
      result.actionText = i18n.translate("Connect")
      
    elseif statecode == "processConnecting" or statecode == "processRestarting"
    then   
      result.state = "connecting"
      result.stateText = i18n.translate("Connecting...")
      result.actionText = i18n.translate("Abort")
    
    elseif statecode == "succesfulConnect"
    then   
      result.state = "connected"
      result.stateText = i18n.translate("Connected")
      result.actionText = i18n.translate("Disconnect")
    
    elseif statecode == "serverChange"
    then   
      result.state = "waiting"
      result.stateText = i18n.translate("Changing Server...")
      result.actionText = i18n.translate("Abort")

    elseif statecode == "connectionModeChange"
    then   
      result.state = "waiting"
      result.stateText = i18n.translate("Changing Connection Mode...")
      result.actionText = i18n.translate("Abort")
      
    elseif     statecode == "failedPassPhrase"
        or statecode == "certificateInvalid"
        or statecode == "allTapInUse"
        or statecode == "notEnoughPrivileges"
        or statecode == "tapDriverTooOld"
        or statecode == "generalError"
        or statecode == "tapDriverNotFound"
        or statecode == "gatewayFailed"
    then
      result.state = "error"
      result.stateText = i18n.translate("Connection Failed")
      result.actionText = i18n.translate("Connect")
    
    else
      result.state = "unknown"
      result.stateText = i18n.translate("Status Unknown")
      result.actionText = i18n.translate("Connect")
    
    end   
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)

    return
end
	
function getAjaxSelectedServer()
    local selectedserver = shellfirebox.getSelectedServerDetails()
    luci.http.prepare_content("application/json")
    luci.http.write_json(selectedserver)

    return
end

function getAjaxConnectionMode()
    luci.http.prepare_content("application/json")
    
    local connectionMode = shellfirebox.getConnectionMode()
    
    luci.http.write_json(tostring(connectionMode))

    return
end

function getAjaxServerList()
    local serverlist = shellfirebox.getServerList()

    luci.http.prepare_content("application/json")
    luci.http.write_json(serverlist)

    return
end
	
function handleAjax()
	
	if luci.http.formvalue("selectedserver") == "1" then
		return getAjaxSelectedServer()
	end

	if luci.http.formvalue("connectionstate") == "1" then
		return getAjaxConnectionState()
	end

	if luci.http.formvalue("serverlist") == "1" then
	  return getAjaxServerList()
	end

  if luci.http.formvalue("serverlistrefresh") == "1" then
    shellfirebox.refreshServerList()
    return
  end

  if luci.http.formvalue("getmessage") == "1" then
    getAjaxFrontEndMessage()
    return
  end

  if luci.http.formvalue("performAction") == "1" then
    if luci.http.formvalue("action") == "abort" then
      shellfirebox.setBlockConnectionStateUpdate(false)
      shellfirebox.abortSetServer()
      shellfirebox.abortSetConnectionMode()
      shellfirebox.disableKillswitch()
      shellfirebox.disconnect()

    elseif luci.http.formvalue("action") == "disconnect" then
      shellfirebox.disableKillswitch()
      shellfirebox.disconnect()
    elseif luci.http.formvalue("action") == "connect" then
      shellfirebox.connectAsync()
    elseif luci.http.formvalue("action") == "setServerTo" then
      shellfirebox.setConnectionState("serverChange")

      if shellfirebox.getConnectionState() == "succesfulConnect" or shellfirebox.getConnectionState() == "processConnecting" then
        shellfirebox.setBlockConnectionStateUpdate(true)
      end

      local serverId = luci.http.formvalue("param")
      shellfirebox.setServerToAsync(serverId)
    elseif luci.http.formvalue("action") == "connectionModeChange" then
      shellfirebox.setConnectionState("connectionModeChange")

      if shellfirebox.getConnectionState() == "succesfulConnect" or shellfirebox.getConnectionState() == "processConnecting" then
        shellfirebox.setBlockConnectionStateUpdate(true)
      end

      local connectionMode = luci.http.formvalue("param")
      shellfirebox.setConnectionModeAsync(connectionMode)
    elseif luci.http.formvalue("action") == "setLanguage" then
      local lang = luci.http.formvalue("param")
      shellfirebox.setLanguage(lang)
      luci.http.redirect(luci.dispatcher.build_url("admin", "services", "shellfirebox"))
    end




    luci.http.write_json("")
    return 
  
  end
  
  local connectionMode = luci.http.formvalue("setConnectionMode")
  if connectionMode ~= nil then
    local msg = setAjaxConnectionMode(connectionMode) 
    return msg
  end

end

function getAjaxAdvancedModeText()
  if shellfirebox.isAdvancedMode() then
    return luci.i18n.translate("Disable Advanced Mode")
  else
    return luci.i18n.translate("Enable Advanced Mode")
  end
end

function getAjaxLanguageText()
  if shellfirebox.getLanguage() == "de" then
    return luci.i18n.translate("Switch to English")
  else
    return luci.i18n.translate("Switch to German")
  end
end

function getAjaxLanguageId()
  return shellfirebox.getLanguage()
end
