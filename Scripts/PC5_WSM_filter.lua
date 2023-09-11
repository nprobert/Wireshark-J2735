--[[
WireShark dissector for PC5 C-V2X protocol for Wireshark
===================================================
Copyright 2019 by D.Khijniak

License
=======
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://urldefense.com/v3/__http://www.gnu.org/licenses/__;!!Bbg-OcCDlOs!RqAi7LnuVUo2FQReh-Wp33FK11-23DQCX07IFNrKktuXuAidN6J_QpLq7FvkBqshNhkM$ >.

Links
=====
WireShark       https://urldefense.com/v3/__http://www.wireshark.org/__;!!Bbg-OcCDlOs!RqAi7LnuVUo2FQReh-Wp33FK11-23DQCX07IFNrKktuXuAidN6J_QpLq7FvkBnZKZnLx$ 

Prerequisites
=============
Wireshark must have an existing decoder for WSMP LLC 0x88DC registered as an ethertype disector

Installation
============
Open Wireshark -> About Wireshark -> Folders 
copy this Lua into folder Personal Plugins or Global Plugins 
or into PortableApps\WiresharkPortable_3.3.0-J27352016\Data\plugins
Ctrl-Shift-L to reload plugins
Open Wireshark -> About Wireshark -> Plugins and check that this lua is included in the plugin listing
Add "wsmp" as filter to remove other udp packets

Changelog
=========
4/27/2019   v0.1     Initial version
12/14/2020  v0.2     Updated and tested with Neal P. Wireshark disector https://urldefense.com/v3/__https://github.com/nprobert/Wireshark-DSRC__;!!Bbg-OcCDlOs!RqAi7LnuVUo2FQReh-Wp33FK11-23DQCX07IFNrKktuXuAidN6J_QpLq7FvkBpDN_E5C$ 
                     using Commsignia pcap logs

]]--
-- get original disector handle ieee1609dot3 based on ethertype
local WSMEthertype = 35036 -- 0x88DC
local dissector_ethertype_table = DissectorTable.get("ethertype")
wsm_disector = dissector_ethertype_table:get_dissector(WSMEthertype)

local pcf_proto = Proto("PC5","C-V2X PC5 Protocol") -- ".name", ".description"

local f_proto_uint16 = ProtoField.uint16("pcf.type","Packet Type") -- Filter name, Column title

pcf_proto.fields = {
		f_proto_uint16
 }
      
-- create a function to dissect protocol
function pcf_proto.dissector(buffer,pinfo,tree)

  length=buffer:len()
  if length == 0 then return end
  
  pinfo.cols.protocol = pcf_proto.name
  
  subtree = tree:add(pcf_proto, buffer (0,1), "PC5 [size: " ..buffer():len().."]")
  subtree:add(f_proto_uint16, buffer(0,1))
   
  newbuf=buffer(1,length-1):tvb()
  if wsm_disector ~= nil then
     wsm_disector:call(newbuf, pinfo, tree)
  end
   
end  

local commsig_proto = Proto("C-DSRC","Commsignia UDP Encapsulation Protocol")

function commsig_proto.dissector(buffer,pinfo,tree)

  local length=buffer:len()
  if length < 60 then return end  -- skip small packets encapsulating commsignia proprietary protocol
  pinfo.cols.protocol = commsig_proto.name

  local strz = buffer:bytes():tohex(true)
  -- print("position: [" .. length .. "] " .. strz) -- check using Wireshark -> Tool -> Lua -> Console
  local i, j = string.find(strz, "88dc")

  if i == nil then 
    print("0x88dc not found")    
    return 
  end
  -- print("position: " .. strz:len() .. "-" .. i )
  subtree = tree:add(commsig_proto, buffer (0,i/2+2), "WSM preamble [size: " ..buffer(0,i/2+2):len().."]")

  newbuf=buffer(i/2+2,length-i/2-2+1):tvb()
  if wsm_disector ~= nil then
       wsm_disector:call(newbuf, pinfo, tree)
  end
   
end  


-- Initialize Protocol
function pcf_proto.init()
end

-- register protocol to handle udp port 1234
local dissector_table = DissectorTable.get("udp.port")
dissector_table:add(1234,pcf_proto)
dissector_table:add(7943,commsig_proto)
-- After change, reload plugin Ctrl-Shift-L (Analyze->Reload Lua plugin