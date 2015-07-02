#!/bin/bash
vmfork_log=/opt/serengeti/logs/instant-clone.log

vmware-rpctool "log JG: end of vmfork; continue customizing child"
echo "start customizing fork child" >> $vmfork_log

# Network configuration: get all the MAC addresses
devices=`ls /sys/class/net | grep en`
for device in $devices
do
  echo $device
  ethLabel=`cat /sys/class/net/$device/device/label`
  mac_addr=`vmware-rpctool "info-get guestinfo.fork.$ethLabel.address"`
  echo "set mac address for $device : $mac_addr : $ethLabel" >> $vmfork_log
  ifconfig $device hw ether $mac_addr
done

# /etc/init.d/network start

# Hostname configuration
new_ip=`ifconfig | grep "inet" | grep -v "127.0.0.1" | grep -v "172."| cut -d: -f 2 | awk '{ print $2 }'`
#newname=$(host $new_ip | cut -d' ' -f 5)
#hostname $newname
#echo $newname > /etc/hostname
vmtoolsd --cmd "info-set guestinfo.ip $new_ip"
#/etc/vmware-tools/init/vmware-tools-services restart

# Disk configuration (if new disks are added)
scsi_hosts=( `ls /sys/class/scsi_host/`)
for host in ${scsi_hosts[@]}; do
   echo "- - -" > /sys/class/scsi_host/$host/scan
done

# Post basic customization
sleep 1
#sed -i '/poll-interval/d' /etc/vmware-tools/tools.conf

# Set file flag for instant clone child vm
echo "set flag for instant clone child" >> $vmfork_log
touch /opt/serengeti/etc/instant_clone_child

echo "finish customizing fork child" >> $vmfork_log
vmware-rpctool "log JG: end of customization"

