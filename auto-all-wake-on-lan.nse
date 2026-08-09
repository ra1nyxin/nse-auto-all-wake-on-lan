local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Aggressively discovers MAC addresses on directly connected IPv4 Ethernet
networks and sends Wake-on-LAN magic packets to every unique address found.

The script needs no arguments by default. It obtains candidates from Nmap host
discovery, an ARP sweep, passive Ethernet traffic, LLTD replies, and, on Linux,
the local ARP cache. Each candidate receives four raw Ethernet WoL frames, four
directed UDP broadcasts, and four limited UDP broadcasts.

This script changes remote device power state. It is deliberately not in the
safe category and must be run with privileges.
]]

---
-- @usage
-- sudo nmap --script auto-all-wake-on-lan
-- sudo nmap -sn -PR 192.168.1.0/24 --script auto-all-wake-on-lan
--
-- @args auto-all-wake-on-lan.interface Interface to use. Defaults to every
--       active IPv4 Ethernet interface. Equivalent to Nmap's -e option.
-- @args auto-all-wake-on-lan.repeat Repetitions per transport, clamped to 3-4.
--       Defaults to 4.
-- @args auto-all-wake-on-lan.timeout Seconds to listen after discovery
--       broadcasts. Defaults to 2s.
-- @args auto-all-wake-on-lan.max-hosts Maximum addresses for an automatic ARP
--       sweep on one interface. Defaults to 65534.
--
-- @output
-- Pre-scan script results:
-- | auto-all-wake-on-lan:
-- |   Interfaces: eth0 (192.168.1.0/24)
-- |   MAC candidates: 12
-- |   Candidate sources: arp-cache=3, arp-sweep=8, lltd=1
-- |_  Sent 144 magic packets (3 transports x 4 repeats x 12 MACs)

author = "rainyxin"
license = "MIT"
categories = {"broadcast", "discovery", "intrusive"}

local SCRIPT = "auto-all-wake-on-lan"
local BROADCAST_MAC = string.rep("\255", 6)
local ZERO_MAC = string.rep("\0", 6)
local MAX_AUTO_HOSTS = 65534

local function registry()
  nmap.registry[SCRIPT] = nmap.registry[SCRIPT] or {
    candidates = {},
    sources = {},
    interfaces = {},
    sent = {},
  }
  return nmap.registry[SCRIPT]
end

local function format_mac(mac)
  return stdnse.format_mac(mac):lower()
end

local function parse_mac(mac)
  if type(mac) ~= "string" then
    return nil
  end
  if #mac == 6 then
    return mac
  end
  local hex = mac:gsub("[^%x]", "")
  if #hex ~= 12 or not hex:match("^%x+$") then
    return nil
  end
  return stdnse.fromhex(hex)
end

local function ipv4_number(ip)
  local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if not a or not b or not c or not d or a > 255 or b > 255 or c > 255 or d > 255 then
    return nil
  end
  return a * 16777216 + b * 65536 + c * 256 + d
end

local function number_ipv4(number)
  local a = math.floor(number / 16777216) % 256
  local b = math.floor(number / 65536) % 256
  local c = math.floor(number / 256) % 256
  local d = number % 256
  return string.format("%d.%d.%d.%d", a, b, c, d)
end

local function netmask_number(netmask)
  if type(netmask) == "number" then
    if netmask < 0 or netmask > 32 then return nil end
    if netmask == 0 then return 0 end
    return (0xffffffff << (32 - netmask)) & 0xffffffff
  end
  return ipv4_number(netmask or "")
end

local function candidate(mac, iface, source)
  mac = parse_mac(mac)
  if not mac or mac == ZERO_MAC or mac == BROADCAST_MAC then
    return false
  end
  if iface and iface.mac == mac then
    return false
  end

  local state = registry()
  local key = format_mac(mac)
  local item = state.candidates[key]
  if not item then
    item = { mac = mac, interfaces = {}, sources = {} }
    state.candidates[key] = item
  end
  if iface then
    item.interfaces[iface.device] = iface
  end
  if source then
    if not item.sources[source] then
      item.sources[source] = true
      state.sources[source] = (state.sources[source] or 0) + 1
    end
  end
  return true
end

local function selected_interfaces()
  local interface_arg = nmap.get_interface() or stdnse.get_script_args(SCRIPT .. ".interface")
  local all = interface_arg and { nmap.get_interface_info(interface_arg) } or nmap.list_interfaces()
  local result = {}
  for _, iface in ipairs(all) do
    if iface and iface.device and iface.address and iface.mac and iface.link == "ethernet"
      and iface.address:match("^%d+%.%d+%.%d+%.%d+$") then
      table.insert(result, iface)
      registry().interfaces[iface.device] = iface
    end
  end
  return result
end

local function arp_packet(iface, destination)
  return BROADCAST_MAC .. iface.mac .. string.char(0x08, 0x06)
    .. string.pack(">I2I2BBI2", 1, 0x0800, 6, 4, 1)
    .. iface.mac .. ipOps.ip_to_str(iface.address) .. ZERO_MAC .. ipOps.ip_to_str(destination)
end

local function discover_arp(iface, timeout_ms, max_hosts, messages)
  local mask = netmask_number(iface.netmask)
  local address = ipv4_number(iface.address)
  if not mask or not address then
    table.insert(messages, ("%s: Nmap did not provide an IPv4 netmask; skipped ARP sweep"):format(iface.device))
    return
  end

  local network = address & mask
  local broadcast = network | ((~mask) & 0xffffffff)
  local host_count = broadcast - network - 1
  if host_count < 1 then
    return
  end
  if host_count > max_hosts then
    table.insert(messages, ("%s: skipped %d-host ARP sweep (limit %d)"):format(iface.device, host_count, max_hosts))
    return
  end

  local dnet, pcap = nmap.new_dnet(), nmap.new_socket()
  local close = function()
    pcall(function() dnet:ethernet_close() end)
    pcall(function() pcap:close() end)
  end
  local ok, err = pcall(function()
    pcap:pcap_open(iface.device, 128, false, "arp and arp[6:2] = 2")
    assert(dnet:ethernet_open(iface.device))
    for target = network + 1, broadcast - 1 do
      if target ~= address then
        assert(dnet:ethernet_send(arp_packet(iface, number_ipv4(target))))
      end
    end
    local deadline = nmap.clock_ms() + timeout_ms
    while nmap.clock_ms() < deadline do
      pcap:set_timeout(math.max(1, deadline - nmap.clock_ms()))
      local status, _, l2, l3 = pcap:pcap_receive()
      if not status then break end
      if l2 and l3 and #l2 >= 12 and #l3 >= 18 then
        candidate(l3:sub(9, 14), iface, "arp-sweep")
      end
    end
  end)
  close()
  if not ok then
    table.insert(messages, ("%s: ARP sweep failed: %s"):format(iface.device, tostring(err)))
  end
end

local function lltd_packet(iface)
  -- LLTD Quick Discovery. We only need the source MAC of any reply.
  return BROADCAST_MAC .. iface.mac .. "\136\217"
    .. "\1\1\0\0" .. BROADCAST_MAC .. iface.mac .. "\0\1"
    .. "\0\1\0\0" .. string.rep("\0", 24)
end

local function discover_lltd(iface, timeout_ms, messages)
  local dnet, pcap = nmap.new_dnet(), nmap.new_socket()
  local close = function()
    pcall(function() dnet:ethernet_close() end)
    pcall(function() pcap:close() end)
  end
  local ok, err = pcall(function()
    pcap:pcap_open(iface.device, 128, false, "ether proto 0x88d9")
    assert(dnet:ethernet_open(iface.device))
    assert(dnet:ethernet_send(lltd_packet(iface)))
    assert(dnet:ethernet_send(lltd_packet(iface)))
    local deadline = nmap.clock_ms() + timeout_ms
    while nmap.clock_ms() < deadline do
      pcap:set_timeout(math.max(1, deadline - nmap.clock_ms()))
      local status, _, l2 = pcap:pcap_receive()
      if not status then break end
      if l2 and #l2 >= 12 then
        candidate(l2:sub(7, 12), iface, "lltd")
      end
    end
  end)
  close()
  if not ok then
    table.insert(messages, ("%s: LLTD discovery failed: %s"):format(iface.device, tostring(err)))
  end
end

local function discover_passive(iface, timeout_ms, messages)
  local pcap = nmap.new_socket()
  local ok, err = pcall(function()
    pcap:pcap_open(iface.device, 64, false, "")
    local deadline = nmap.clock_ms() + timeout_ms
    while nmap.clock_ms() < deadline do
      pcap:set_timeout(math.max(1, deadline - nmap.clock_ms()))
      local status, _, l2 = pcap:pcap_receive()
      if not status then break end
      if l2 and #l2 >= 12 then
        candidate(l2:sub(7, 12), iface, "passive-ethernet")
      end
    end
  end)
  pcall(function() pcap:close() end)
  if not ok then
    table.insert(messages, ("%s: passive capture failed: %s"):format(iface.device, tostring(err)))
  end
end

local function discover_linux_arp_cache(interfaces)
  local by_device = {}
  for _, iface in ipairs(interfaces) do by_device[iface.device] = iface end
  local file = io.open("/proc/net/arp", "r")
  if not file then return end
  for line in file:lines() do
    local _, flags, mac, device = line:match("^(%S+)%s+(0x%x+)%s+(%S+)%s+(%S+)")
    if flags and mac and device and (tonumber(flags) or 0) % 4 >= 2 then
      candidate(mac, by_device[device], "arp-cache")
    end
  end
  file:close()
end

local function wol_payload(mac)
  return string.rep("\255", 6) .. string.rep(mac, 16)
end

local function send_udp_wol(address, payload, repeats)
  local sent = 0
  local ok = pcall(function()
    local socket = nmap.new_socket("udp")
    local host = { ip = address }
    local port = { number = 9, protocol = "udp" }
    for _ = 1, repeats do
      if socket:sendto(host, port, payload) then sent = sent + 1 end
    end
    socket:close()
  end)
  return ok and sent or 0
end

local function wake(candidate_item, repeats)
  local state = registry()
  local mac_key = format_mac(candidate_item.mac)
  if state.sent[mac_key] then return 0 end
  state.sent[mac_key] = true

  local payload = wol_payload(candidate_item.mac)
  local sent = 0
  for _, iface in pairs(candidate_item.interfaces) do
    local dnet = nmap.new_dnet()
    local opened = dnet:ethernet_open(iface.device)
    if opened then
      local frame = BROADCAST_MAC .. iface.mac .. string.char(0x08, 0x42) .. payload
      for _ = 1, repeats do
        if dnet:ethernet_send(frame) then sent = sent + 1 end
      end
      dnet:ethernet_close()
    end

    -- The interface broadcast address is preferred; the limited broadcast is
    -- included because some WoL implementations only listen on it.
    if iface.broadcast then
      sent = sent + send_udp_wol(iface.broadcast, payload, repeats)
    end
    sent = sent + send_udp_wol("255.255.255.255", payload, repeats)
  end
  return sent
end

local function wake_all(repeats)
  local sent = 0
  for _, item in pairs(registry().candidates) do
    sent = sent + wake(item, repeats)
  end
  return sent
end

local function summary(messages, sent)
  local state = registry()
  local interfaces, sources = {}, {}
  for _, iface in pairs(state.interfaces) do
    table.insert(interfaces, iface.device .. " (" .. iface.address .. ")")
  end
  table.sort(interfaces)
  for source, count in pairs(state.sources) do
    table.insert(sources, source .. "=" .. count)
  end
  table.sort(sources)
  local count = 0
  for _ in pairs(state.candidates) do count = count + 1 end
  local output = {
    "Interfaces: " .. (#interfaces > 0 and table.concat(interfaces, ", ") or "none"),
    "MAC candidates: " .. count,
    "Candidate sources: " .. (#sources > 0 and table.concat(sources, ", ") or "none"),
    ("Sent %d magic packets"):format(sent),
  }
  for _, message in ipairs(messages) do table.insert(output, message) end
  return stdnse.format_output(true, output)
end

prerule = function()
  return nmap.is_privileged() and nmap.address_family() == "inet"
end

hostrule = function(host)
  return host.mac_addr ~= nil and host.interface ~= nil
end

action = function(host)
  local repeats = tonumber(stdnse.get_script_args(SCRIPT .. ".repeat")) or 4
  repeats = math.max(3, math.min(4, math.floor(repeats)))

  if host then
    local iface = nmap.get_interface_info(host.interface)
    if candidate(host.mac_addr, iface, "nmap-host-discovery") then
      local item = registry().candidates[format_mac(host.mac_addr)]
      local sent = wake(item, repeats)
      if sent > 0 then
        return ("Sent %d magic packets to %s"):format(sent, format_mac(host.mac_addr))
      end
    end
    return
  end

  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT .. ".timeout")) or 2
  local max_hosts = tonumber(stdnse.get_script_args(SCRIPT .. ".max-hosts")) or MAX_AUTO_HOSTS
  max_hosts = math.max(1, math.floor(max_hosts))
  local messages, interfaces = {}, selected_interfaces()
  if #interfaces == 0 then
    return stdnse.format_output(false, "No active IPv4 Ethernet interface found")
  end

  discover_linux_arp_cache(interfaces)
  for _, iface in ipairs(interfaces) do
    discover_arp(iface, timeout * 1000, max_hosts, messages)
    discover_lltd(iface, timeout * 1000, messages)
    discover_passive(iface, timeout * 1000, messages)
  end
  return summary(messages, wake_all(repeats))
end
