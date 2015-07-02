#!/usr/bin/python

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
try:
  import json
except ImportError:
  import simplejson as json
from xml.dom.minidom import parseString

def get_vmfork_config():
  try:
    machine_id = os.popen('/bin/vmware-rpctool machine.id.get').read()
    return (json.loads(machine_id)['vmfork'])
  except:
    os.system('echo "there is no vmfork configuration" >> /opt/serengeti/logs/instant-clone.log')
    return None

def main():
  # fetch vmfork configuration from machine.id
  vmfork_config = get_vmfork_config()
  if vmfork_config is None:
    os.system('echo "boot normally" >> /opt/serengeti/logs/instant-clone.log')
    return
  print "vmfork config: " + vmfork_config
  os.system('echo "' + vmfork_config + '" > /opt/serengeti/etc/instant_clone_config')

if __name__ == '__main__':
  main()


