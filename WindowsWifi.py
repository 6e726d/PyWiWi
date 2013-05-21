# PyWiWi - Windows Native Wifi Api Python library.
# Copyright (C) 2013 - Andres Blanco
#
# This file is part of PyWiWi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Author: Andres Blanco (6e726d) <6e726d@gmail.com>
#

from ctypes import addressof

from WindowsNativeWifiApi import *


class WirelessInterface(object):
    def __init__(self, wlan_iface_info):
        self.description = wlan_iface_info.strInterfaceDescription
        self.guid = wlan_iface_info.InterfaceGuid
        self.state = wlan_iface_info.isState
        self.state_string = WLAN_INTERFACE_STATE_DICT[self.state]

    def __str__(self):
        result = ""
        result += "Description: %s\n" % self.description
        result += "GUID: %s\n" % self.guid
        result += "State: %s\n" % self.state_string
        return result


def getWirelessInterfaces():
    """Returns a list of WirelessInterface objects based on the wireless
       interfaces available."""
    interfaces_list = []
    handle = WlanOpenHandle()
    wlan_ifaces = WlanEnumInterfaces(handle)
    # Handle the WLAN_INTERFACE_INFO_LIST pointer to get a list of
    # WLAN_INTERFACE_INFO structures.
    data_type = wlan_ifaces.contents.InterfaceInfo._type_
    num = wlan_ifaces.contents.NumberOfItems
    ifaces_pointer = addressof(wlan_ifaces.contents.InterfaceInfo)
    wlan_interface_info_list = (data_type * num).from_address(ifaces_pointer)
    for wlan_interface_info in wlan_interface_info_list:
        wlan_iface = WirelessInterface(wlan_interface_info)
        interfaces_list.append(wlan_iface)
    WlanFreeMemory(wlan_ifaces)
    WlanCloseHandle(handle)
    return interfaces_list


def getWirelessNetworkBssList(wireless_interface):
    """Returns a list of WirelessNetworkBss objects based on the wireless
       networks availables."""
    networks = []
    handle = WlanOpenHandle()
    print "-" * 5
    print wireless_interface
    print wireless_interface.guid
    print "-" * 5
    return
    bss_list = WlanGetNetworkBssList(handle, wireless_interface.guid)
    # Handle the WLAN_BSS_LIST pointer to get a list of WLAN_BSS_ENTRY
    # structures.
    data_type = bss_list.contents.wlanBssEntries._type_
    num = bss_list.contents.NumberOfItems
    bsss_pointer = addressof(bss_list.contents.wlanBssEntries)
    bss_entries_list = (data_type * num).from_address(bsss_pointer)
    for bss_entry in bss_entries_list:
        print bss_entry


if __name__ == "__main__":
    ifaces = getWirelessInterfaces()
    for iface in ifaces:
        print iface
        guid = iface.guid
        getWirelessNetworkBssList(iface)
