#!/bin/sh

# ***** BEGIN LICENSE BLOCK *****
# Copyright (c) 2013-2014 VMware, Inc. All Rights Reserved.
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

# run serengeti scirpt on every boot

# Set the private keys file permission to 400. Although it's not a Serengeti bug.
if ls /opt/vmware/etc/sfcb/*.pem &>/dev/null; then
  chmod 400 /opt/vmware/etc/sfcb/*.pem
fi

vmfork_log=/opt/serengeti/logs/instant-clone.log

# check if vmfork is set in machine id, and yes will generate the flag file.
python /opt/serengeti/sbin/instant-clone.py

# check if the instant_clone_config flag file is created.
if [ -f /opt/serengeti/etc/instant_clone_config ];
then
  is_instant_clone=yes
  echo "start vmfork" >> $vmfork_log
#  dhclient -v -r;
  /etc/init.d/network stop;/bin/vmware-rpctool "vmfork-begin -1 -1";/opt/serengeti/sbin/customize-child.sh >> $vmfork_log;
  echo "finish vmfork, continue normal boot process" >> $vmfork_log
fi

# rescan paravirtual controllers
#bash /opt/serengeti/sbin/rescan-controllers.sh

# run serengeti scirpt on every boot
#python /opt/serengeti/sbin/shutdown-ssh-access.py &
#python /opt/serengeti/sbin/format-disk.py &
wait

if [ $is_instant_clone ] && [ ! -f /opt/serengeti/etc/instant_clone_child ]; then
  echo "this is parent vm" >> $vmfork_log
  is_parent=yes
fi
if [ ! $is_parent ]; then
  echo "this is not parent vm" >> $vmfork_log
  python /opt/serengeti/sbin/setup-ip.py &
  wait
fi
