

# ***** BEGIN LICENSE BLOCK *****
# Copyright (c) 2013 VMware, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ***** END LICENSE BLOCK *****
"""Implementation of Serengeti's Ip Addresses Configuration
"""
import sys
import os
import re
import time
import socket
import os.path
try:
  import json
except ImportError:
  import simplejson as json
from xml.dom.minidom import parseString

def write_file(file_name, content):
  os.system("[ -f %s ] && cp %s %s" % (file_name, file_name, file_name + "~"))
  f = open(file_name, 'w')
  f.write(content)
  f.close()

def get_nics_config():
  try:
    machine_id = os.popen('/bin/vmware-rpctool machine.id.get').read()
    # WS api actually call json.to_json twice for non-String object,
    # so here we have to deserialize 'nics' array twice, although it's ugly
    return (json.loads(machine_id)['portgroup'], json.loads(json.loads(machine_id)['nics']))
  except:
    print "failed to fetch nics configuration"
    return None

# in multipe networks env, each NICs configuration might be differnt, 
# but NICs' device name assignment is not in a fixed order, to make sure
# each NIC configuration is exactly applied to desired portgroup, we
# fetch (portgroup<->mac_address) info from guestinfo.ovfEnv, and
# (dev_name<->mac_address) info from OS PCI dump, WS transfers
# the (portgroup<->ip_config) info to machine.id, by merging these info,
# we can configure ethX as expectation
def network_to_device_map():
  try:
    net2mac = {}
    guest_info = os.popen('/bin/vmware-rpctool \'info-get guestinfo.ovfEnv\'').read()
    dom = parseString(guest_info)
    ethSection = dom.getElementsByTagName('Environment')[0].getElementsByTagName('ve:EthernetAdapterSection')[0]
    eths = ethSection.getElementsByTagName('ve:Adapter')
    for eth in eths:
      network_name = None
      mac_address = None
      for name, value in eth.attributes.items():
        if name == 've:network':
          network_name = value
        if name == 've:mac':
          mac_address = value
      net2mac[network_name] = mac_address

    mac2dev = {}
    basedir = '/sys/class/net'
    for dev_name in os.listdir(basedir):
      if re.match(r'^eno', dev_name):
        filename = os.path.join(basedir, dev_name, 'address')
        mac_address = open(filename).readline().strip('\n')
        mac2dev[mac_address] = dev_name

    net2dev = {}
    for net, mac in net2mac.items():
      if mac2dev.has_key(mac):
        dev = mac2dev[mac]
        net2dev[net] = dev

    # dump portgroup_to_net_device map info.
    # This is because: WS now send a ip_config info to ironfan and saved as node[:ip_configs],
    # this field is not able to be auto updated if user manually restart vm(also for VHM).
    # in this case, cookbooks will not able to be aware if ips changed.
    # So we save portgroup_to_netdev_map to a local file, when chef-client launched,
    # we can update node[:ip_configs] field by ourselves.
    print "net2dev: " + json.dumps(net2dev)
    write_file('/etc/portgroup2eth.json', json.dumps(net2dev))
    return net2dev
  except:
    raise

# assume eth0 always exist
def has_configured_nic():
  f = open("/etc/sysconfig/network-scripts/ifcfg-eth0", 'r')
  for line in f:
    if re.compile("BOOTPROTO").match(line):
      f.close()
      return True
  f.close()
  return False

def setup_dhcp_network(device, nic_config):
  template = """
ONBOOT=yes
STARTMODE=manual
DEVICE=%s
BOOTPROTO=dhcp
DHCLIENT_RELEASE_BEFORE_QUIT=yes"""
  print 'setup dhcp network for device %s' % device
  template = template.lstrip()
  items = []
  items.append(template % device)
  if not nic_config is None and nic_config.has_key('dnsType') and nic_config['dnsType'] == 'DYNAMIC' and nic_config.has_key('dhcpHostname') and nic_config['dhcpHostname']:
    items.append("DHCP_HOSTNAME=%s" % nic_config['dhcpHostname'])
  write_file('/etc/sysconfig/network-scripts/ifcfg-%s' % device, '\n'.join(items))

def setup_static_network(device, nic_config):
  template = """
TYPE=Ethernet
ONBOOT=yes
DEVICE=%s
NAME=%s
BOOTPROTO=static
DEFROUTE=yes
PEERDNS=yes
PEERROUTES=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=yes
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV6_PEERDNS=yes
IPV6_PEERROUTES=yes
IPV6_FAILURE_FATAL=no
IPADDR=%s"""
  print 'setup static network for device %s' % device
  template = template.lstrip()
  items = []
  items.append(template % (device, device, nic_config['ipaddr']))
  if nic_config.has_key('netmask') and not nic_config['netmask'] is None:
    items.append("NETMASK=%s" % nic_config['netmask'])
  if nic_config.has_key('gateway') and not nic_config['gateway'] is None:
    items.append("GATEWAY=%s" % nic_config['gateway'])
  if nic_config.has_key('dnsType') and nic_config['dnsType'] == 'DYNAMIC' and nic_config.has_key('dhcpHostname') and nic_config['dhcpHostname']:
    items.append("DHCP_HOSTNAME=%s" % nic_config['dhcpHostname'])
  if nic_config.has_key('dnsserver0') and nic_config['dnsserver0']:
    items.append("DNS1=%s" % nic_config['dnsserver0'])
  if nic_config.has_key('dnsserver1') and nic_config['dnsserver1']:
    items.append("DNS2=%s" % nic_config['dnsserver1'])

  write_file('/etc/sysconfig/network-scripts/ifcfg-%s' % device, '\n'.join(items))

def add_dns_servers(dns_servers):
  print "DNS servers: %s" % str(dns_servers)
  if len(dns_servers) > 0:
    dns_conf = ""
    for dns in dns_servers:
      dns_conf += "nameserver " + dns + "\n"
    write_file('/etc/resolv.conf', dns_conf)

def retrieve_dhcp_route_entry(device):
  route_entry = {}
  # Currently I cannot find a better way to retrieve subnet/netmask/gateway info
  # of a specified device, so have to parse dhclient's lease files.
  # The potential issue is lease file format may varies for different OSs
  f = open('/var/lib/dhclient/dhclient--%s.lease' % device)
  lines = []
  for l in f:
    lines.append(l)
  f.close()
  # search from end to begin to fetch the latest lease item
  for line in reversed(lines):
    if re.compile('routers').search(line) and not route_entry.has_key('gateway'):
      # this item is called "routers" rather than "router", so may be multiple values, if it is,
      # it should be splitted by "," as same with "domain-name-servers"
      route_entry['gateway'] = re.split('\s+', line)[3].split(',')[0].replace(';', '')
    if re.compile('fixed-address').search(line) and not route_entry.has_key('ipaddr'):
      route_entry['ipaddr'] = re.split('\s+', line)[2].replace(';', '')
    if re.compile('subnet-mask').search(line) and not route_entry.has_key('netmask'):
      route_entry['netmask'] = re.split('\s+', line)[3].replace(';', '')
  #TODO, error handling, if failed to fetch gateway/ipaddr/subnet-mask
  return route_entry

def retrieve_static_route_entry(nic_config):
  route_entry = {}
  route_entry['ipaddr'] = nic_config['ipaddr']
  if nic_config.has_key('netmask') and not nic_config['netmask'] is None:
    route_entry['netmask'] = nic_config['netmask']
  if nic_config.has_key('gateway') and not nic_config['gateway'] is None:
    route_entry['gateway'] = nic_config['gateway']

  return route_entry

# calculate subnet of a device, i.e, ipaddr is 192.168.100.1, mask is 255.255.255.0, then
# subnet is 192.168.100.0
def calc_subnet(ip, mask):
  ip_parts = re.split('\.', ip)
  mask_parts = re.split('\.', mask)
  subnet_parts = []
  mask_length = 32
  for i in range(4):
    ip_part = int(ip_parts[i])
    mask_part = int(mask_parts[i])
    subnet_parts.append(str(ip_part & mask_part))
    mask_part ^= 255
    while mask_part != 0:
      mask_part /= 2
      mask_length -= 1
  return ".".join(subnet_parts) + "/" + str(mask_length)

def set_fqdn_registered_status(code, status):
   os.system("/bin/vmware-rpctool 'info-set guestinfo.fqdn.register.status %s'" % status);
   os.system("/bin/vmware-rpctool 'info-set guestinfo.FqdnRegisterCode %s'" % code);

def get_route_entries(nics_config, net2dev):
  route_entries = {}
  for nic_config in nics_config:
    device = net2dev[nic_config['portgroup']]
    proto = nic_config['bootproto']
    if proto == 'static':
      route_entry = retrieve_static_route_entry(nic_config)
    else:
      route_entry = retrieve_dhcp_route_entry(device)

    route_entries[device] = route_entry

  return route_entries

def get_fqdn_from_ip(ipaddr, is_dynamic, dhcp_hostname, device):
  fqdn = ""
  fqdn_sleep_time = 3
  fqdn_timeout = 600
  while (not fqdn and fqdn_timeout != 0):
    try:
      if hasattr(socket, 'setdefaulttimeout'):
        socket.setdefaulttimeout(5)
      fqdn = socket.gethostbyaddr(ipaddr)[0]
      if is_dynamic:
        if dhcp_hostname:
          if dhcp_hostname in fqdn:
            print "OK: FQDN " + fqdn + " expected " + dhcp_hostname
          else:
            fqdn = ""
            time.sleep(fqdn_sleep_time)
            fqdn_timeout -= fqdn_sleep_time
        else:
          break
      if fqdn:
        print "FQDN " + fqdn + " get from IP address %s successfully" % ipaddr
    except:
      print "Failed to get fqdn from IP address %s" % ipaddr
      time.sleep(fqdn_sleep_time)
      fqdn_timeout -= fqdn_sleep_time

  if fqdn_timeout <= 0:
    print "Timeout to get FQDN from IP address %s" % ipaddr

  return fqdn

def wait_fqdn_registered(nics_config, net2dev):
  registered_fqdn_count = 0
  need_register_fqdn_count = 0

  route_entries = get_route_entries(nics_config, net2dev)

  for nic_config in nics_config:
    for net in net2dev.keys():
      if net == nic_config['portgroup']:

        dnsType = ""
        if nic_config.has_key('dnsType'):
          dnsType = nic_config['dnsType']

        dhcpHostname = ""
        if nic_config.has_key('dhcpHostname') and nic_config['dhcpHostname']:
          dhcpHostname = nic_config['dhcpHostname']

        if dnsType != 'DYNAMIC':
          continue

        if not dhcpHostname:
          continue

        need_register_fqdn_count += 1

        device = net2dev[net]
        route_entry = route_entries[device]
        ipaddr = route_entry['ipaddr']
        fqdn = get_fqdn_from_ip(ipaddr, True, dhcpHostname, device)
        if fqdn:
          registered_fqdn_count += 1

  print "There are %s FQDN need to register" % need_register_fqdn_count
  print "%s FQDN register successfully" % registered_fqdn_count

  if registered_fqdn_count == need_register_fqdn_count:
    set_fqdn_registered_status("0", "FQDN of all NICs are registered")
  else:
    set_fqdn_registered_status("-1", "Failed to regiester FQDN")

def set_network_info(nics_config, net2dev):
  network_info = {'nics': []}

  route_entries = get_route_entries(nics_config, net2dev)

  for nic_config in nics_config:
    for net in net2dev.keys():
      if net == nic_config['portgroup']:
        nic_info = {}
        nic_info['portgroup'] = net
        device = net2dev[net]
        nic_info['device'] = device
        dns_type = 'NORMAL'
        if nic_config.has_key('dnsType') and nic_config['dnsType']:
          dns_type = nic_config['dnsType']
        route_entry = route_entries[device]
        ipaddr = route_entry['ipaddr']
        nic_info['ipaddr'] = ipaddr
        fqdn = ""
        if dns_type == 'OTHERS' or (dns_type == 'NORMAL' and nic_config.has_key('dhcpHostname') and nic_config['dhcpHostname']):
          fqdn = nic_config['dhcpHostname']
        else:
          dhcpHostname = ""
          if nic_config.has_key('dhcpHostname') and nic_config['dhcpHostname']:
            dhcpHostname = nic_config['dhcpHostname']
          fqdn = get_fqdn_from_ip(ipaddr, dns_type == 'DYNAMIC', dhcpHostname, device)
        nic_info['fqdn'] = fqdn
        network_info['nics'].append(nic_info)
  print json.dumps(network_info)
  os.system("/bin/vmware-rpctool 'info-set guestinfo.network_info %s'" % json.dumps(network_info))

def update_network_configurations(nics_config, net2dev):
  dns_servers = []
  for nic_config in nics_config:
    device = net2dev[nic_config['portgroup']]
    if device is None:
      print "cannot find device for portgroup: %s, ignore it" % nic_config['portgroup']
      continue
    if nic_config.has_key('dnsserver0') and (nic_config['dnsserver0'] not in dns_servers):
      dns_servers.append(nic_config['dnsserver0'])
    if nic_config.has_key('dnsserver1') and (nic_config['dnsserver1'] not in dns_servers):
      dns_servers.append(nic_config['dnsserver1'])

    if not need_update(device, nic_config):
      continue

    proto = nic_config['bootproto']
    if proto == 'static':
      setup_static_network(device, nic_config)
    else:
      setup_dhcp_network(device, nic_config)
    add_dns_servers(dns_servers)

def update_ip_route(nics_config, net2dev, default_device):
  if len(nics_config) > 1:
    route_entries = get_route_entries(nics_config, net2dev)
    print "route_info: " + str(route_entries)

    ip_rule_priority_base = 100
    ip_rule_conf_file = '/etc/iproute2/rt_tables'
    for device in route_entries.keys():
      route_entry = route_entries[device]
      subnet = calc_subnet(route_entry['ipaddr'], route_entry['netmask'])
      table_name = "device_" + device
      priority = str(ip_rule_priority_base)
      ip_rule_priority_base += 1

      table_defined = False
      f = open(ip_rule_conf_file, 'r')
      for line in f:
        if re.compile(table_name).match(line):
          table_defined = True
          break
      f.close()
      if not table_defined:
        os.system('echo %s %s >> %s' % (priority, table_name, ip_rule_conf_file))
      os.system('/sbin/ip route add %s dev %s src %s table %s' % (subnet, device, route_entry['ipaddr'], table_name))
      if route_entry.has_key('gateway') and not route_entry['gateway'] is None:
        os.system('/sbin/ip route add default via %s table %s' % (route_entry['gateway'], table_name))
        if device == default_device:
          current_default_gw = os.popen('/sbin/ip route list match 0/0 | grep default | awk \'{print $3}\'').read()
          if current_default_gw != route_entry['gateway']:
            os.system('/sbin/route del default gw %s' % current_default_gw)
            os.system('/sbin/ip route add default via %s' % route_entry['gateway'])
      os.system('/sbin/ip rule add from %s table %s' % (route_entry['ipaddr'], table_name))
    os.system('/sbin/ip route flush cache')

def need_update(device, nic_config):
  need_update = False

  configurations = []

  proto = nic_config['bootproto']

  configurations.append("BOOTPROTO=%s" % proto)

  if nic_config.has_key('dnsType') and nic_config['dnsType'] == 'DYNAMIC' and nic_config.has_key('dhcpHostname') and nic_config['dhcpHostname']:
    configurations.append("DHCP_HOSTNAME=%s" % nic_config['dhcpHostname'])

  if proto == 'static':
    configurations.append("IPADDR=%s" % nic_config['ipaddr'])
    if nic_config.has_key('netmask') and not nic_config['netmask'] is None:
      configurations.append("NETMASK=%s" % nic_config['netmask'])
    if nic_config.has_key('gateway') and not nic_config['gateway'] is None:
      configurations.append("GATEWAY=%s" % nic_config['gateway'])

  nic_conf_file = "/etc/sysconfig/network-scripts/ifcfg-%s" % device

  if not os.path.isfile(nic_conf_file):
    return True

  for configuration in configurations:
    isExisted = os.system('grep %s %s > /dev/null' % (configuration, nic_conf_file))
    if not isExisted == 0:
      need_update = True
      break

  return need_update

def need_restart_network(nics_config, net2dev):
  need_restart_network = False

  for nic_config in nics_config:
    portgroup = nic_config['portgroup']
    device = net2dev[portgroup]
    if device is None:
      print "cannot find device for portgroup: %s, ignore it" % portgroup
      continue

    if need_update(device, nic_config):
      need_restart_network = True
      break

  # for instant clone, the node network might have not been started till now
  # so we need check it and start it if not started
  if not need_restart_network:
    net_started = False
    netstatus = os.popen('/etc/init.d/network status')
    is_status_line = False
    for line in netstatus:
      if is_status_line and line.strip() != '':
        net_started = True
      if line.find('Currently active devices:') != -1:
        is_status_line = True
    if not net_started:
      need_restart_network = True

  return need_restart_network

def is_nics_config_existed(nics_config):
  if nics_config:
    return True
  else:
    if has_configured_nic():
      print "No machine.id found and has configured nic, start netowk with last boot's settings"
    else:
      # when powering on template vm, setup eth0 to dhcp to retrieve IP
      setup_dhcp_network('eth0', None)
    return False

def main():

  set_fqdn_registered_status("1", "Preparing FQDN")

  if not get_nics_config():
    return

  # fetch NICs configuration from machine.id
  default_pgname, nics_config = get_nics_config()
  print "NICs config: " + str(nics_config)

  # fetch portgroup name to device name hashmap by
  # querying guestinfo and os
  net2dev = network_to_device_map()
  print "network to device map: " + str(net2dev)
  default_device = net2dev[default_pgname]

  if not is_nics_config_existed(nics_config):
    return

  need_restart = need_restart_network(nics_config, net2dev)

  update_network_configurations(nics_config, net2dev)

  if need_restart:
    print "Restarting network service."
    os.system('systemctl restart network')
  else:
    print "No need to restart network service."

  #update_ip_route(nics_config, net2dev, default_device)

  wait_fqdn_registered(nics_config, net2dev)

  set_network_info(nics_config, net2dev)

if __name__ == '__main__':
  main()
