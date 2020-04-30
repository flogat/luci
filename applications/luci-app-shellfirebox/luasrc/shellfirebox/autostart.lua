#!/usr/bin/lua
local shellfirebox = require "luci.shellfirebox"
local debugger = require "luci.debugger"
local serverListRefreshed = false
local openVpnParamsRefreshed = false
local webServiceAliasRefreshed = false
local vpnRefreshed = false

shellfirebox.led.blinkAsync()

while serverListRefreshed == false do
  debugger.log("autostarter - refreshServerList - performing refresh")
  serverListRefreshed = shellfirebox.refreshServerList()
  debugger.log("autostarter - refreshServerList - result: " .. tostring(serverListRefreshed))

  if serverListRefreshed == false then
    debugger.log("autostarter - refreshServerList - sleeping 10 seconds")
    luci.sys.exec("sleep 10")
  end
end

while openVpnParamsRefreshed == false do
  debugger.log("autostarter - refreshOpenVpnParams - performing refresh")
  openVpnParamsRefreshed = shellfirebox.refreshOpenVpnParams()
  debugger.log("autostarter - refreshOpenVpnParams - result: " .. tostring(openVpnParamsRefreshed))

  if openVpnParamsRefreshed == false then
    debugger.log("autostarter - refreshOpenVpnParams - sleeping 10 seconds")
    luci.sys.exec("sleep 10")
  end
end


while vpnRefreshed == false do                                                                                                                                     
  debugger.log("autostarter - refreshVpn - performing refresh")                                                                                                    
  vpnRefreshed = shellfirebox.refreshVpn()             
  debugger.log("autostarter - refreshVpn - result: " .. tostring(vpnRefreshed))
                                                                                                                                                                             
  if vpnRefreshed == false then                                                                                                                                    
    debugger.log("autostarter - refreshVpn - sleeping 10 seconds")                                                                                                 
    luci.sys.exec("sleep 10")                                                                                                                                                
  end                                                                                                                                                                        
end     


while webServiceAliasRefreshed == false do                                                     
  debugger.log("autostarter - refreshWebServiceAliasList - performing refresh")                    
  webServiceAliasRefreshed = shellfirebox.refreshWebServiceAliasList()                                     
  debugger.log("autostarter - refreshWebServiceAliasList - result: " .. tostring(webServiceAliasRefreshed))
                                                                                                   
  if webServiceAliasRefreshed == false then                                                          
    debugger.log("autostarter - refreshWebServiceAliasList - sleeping 10 seconds")                       
    luci.sys.exec("sleep 10")                                                                      
  end                                                                                              
end

debugger.log("autostarter - now that we reached this place, we can fairly assume that after a reboot internet is available - performing an update of all packages")
luci.sys.exec("/usr/lib/lua/luci/shellfirebox/scripts/updater.sh >> /tmp/syslog.log")
debugger.log("autostart.sh - package-update finished")


if shellfirebox.getAutostartRequested() == "true" then
  debugger.log("autostarter - autostartRequested is true, so connecting")
  shellfirebox.connectAsync()
else
  debugger.log("autostarter - autostartRequested is false, so doing nothing")
  shellfirebox.led.off()
end
    
