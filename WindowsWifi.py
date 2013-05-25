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

from ctypes import *
from comtypes import GUID
from WindowsNativeWifiApi import *


class WirelessInterface(object):
    def __init__(self, wlan_iface_info):
        self.description = wlan_iface_info.strInterfaceDescription
        self.guid = GUID(wlan_iface_info.InterfaceGuid)
        self.guid_string = str(wlan_iface_info.InterfaceGuid)
        self.state = wlan_iface_info.isState
        self.state_string = WLAN_INTERFACE_STATE_DICT[self.state]

    def __str__(self):
        result = ""
        result += "Description: %s\n" % self.description
        result += "GUID: %s\n" % self.guid
        result += "State: %s" % self.state_string
        return result


class InformationElement(object):
    def __init__(self, element_id, length, body):
        self.element_id = element_id
        self.length = length
        self.body = body

    def __str__(self):
        result = ""
        result += "Element ID: %d\n" % self.element_id
        result += "Length: %d\n" % self.length
        result += "Body: %r" % self.body
        return result


class WirelessNetworkBss(object):
    def __init__(self, bss_entry):
        self.ssid = bss_entry.dot11Ssid.SSID[:DOT11_SSID_MAX_LENGTH]
        self.link_quality = bss_entry.LinkQuality
        self.bssid = ":".join(map(lambda x: "%02X" % x, bss_entry.dot11Bssid))
        self.bss_type = DOT11_BSS_TYPE_DICT[bss_entry.dot11BssType]
        self.phy_type = DOT11_PHY_TYPE_DICT[bss_entry.dot11BssPhyType]
        self.rssi = bss_entry.Rssi
        self.capabilities = bss_entry.CapabilityInformation
        self.__process_information_elements(bss_entry)
        self.__process_information_elements2()

    def __process_information_elements(self, bss_entry):
        self.raw_information_elements = ""
        bss_entry_pointer = addressof(bss_entry)
        ie_offset = bss_entry.IeOffset
        data_type = (c_char * bss_entry.IeSize)
        ie_buffer = data_type.from_address(bss_entry_pointer + ie_offset)
        for byte in ie_buffer:
            self.raw_information_elements += byte

    def __process_information_elements2(self):
        MINIMAL_IE_SIZE = 3
        self.information_elements = []
        aux = self.raw_information_elements
        index = 0
        while(index < len(aux) - MINIMAL_IE_SIZE):
            eid = ord(aux[index])
            index += 1
            length = ord(aux[index])
            index += 1
            body = aux[index:index + length]
            index += length
            ie = InformationElement(eid, length, body)
            self.information_elements.append(ie)

    def __str__(self):
        result = ""
        result += "BSSID: %s\n" % self.bssid
        result += "SSID: %s\n" % self.ssid
        result += "Link Quality: %d%%\n" % self.link_quality
        result += "BSS Type: %s\n" % self.bss_type
        result += "PHY Type: %s\n" % self.phy_type
        result += "Capabilities: %d\n" % self.capabilities
        # result += "Raw Information Elements:\n"
        # result += "%r" % self.raw_information_elements
        result += "\nInformation Elements:\n"
        for ie in self.information_elements:
            lines = str(ie).split("\n")
            for line in lines:
                result += " + %s\n" % line
            result += "\n"
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
    bss_list = WlanGetNetworkBssList(handle, wireless_interface.guid)
    # Handle the WLAN_BSS_LIST pointer to get a list of WLAN_BSS_ENTRY
    # structures.
    data_type = bss_list.contents.wlanBssEntries._type_
    num = bss_list.contents.NumberOfItems
    bsss_pointer = addressof(bss_list.contents.wlanBssEntries)
    bss_entries_list = (data_type * num).from_address(bsss_pointer)
    for bss_entry in bss_entries_list:
        networks.append(WirelessNetworkBss(bss_entry))
    return networks
