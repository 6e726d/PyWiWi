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
# Author: Andres Blanco (6e726d)     <6e726d@gmail.com>
#

from ctypes import *

from comtypes import GUID

from ctypes.wintypes import BOOL
from ctypes.wintypes import DWORD
from ctypes.wintypes import HANDLE

ERROR_SUCCESS = 0

CLIENT_VERSION_WINDOWS_XP_SP3 = 1
CLIENT_VERSION_WINDOWS_VISTA_OR_LATER = 2

DOT11_SSID_MAX_LENGTH = 32

wlanapi = windll.LoadLibrary('wlanapi.dll')

# The WLAN_INTERFACE_STATE enumerated type indicates the state of an interface.
WLAN_INTERFACE_STATE = c_uint
WLAN_INTERFACE_STATE_DICT = {0: "wlan_interface_state_not_ready",
                             1: "wlan_interface_state_connected",
                             2: "wlan_interface_state_ad_hoc_network_formed",
                             3: "wlan_interface_state_disconnecting",
                             4: "wlan_interface_state_disconnected",
                             5: "wlan_interface_state_associating",
                             6: "wlan_interface_state_discovering",
                             7: "wlan_interface_state_authenticating"}

# The DOT11_BSS_TYPE enumerated type defines a basic service set (BSS) network
# type.
DOT11_BSS_TYPE = c_uint
DOT11_BSS_TYPE_DICT = {1: "dot11_BSS_type_infrastructure",
                       2: "dot11_BSS_type_independent",
                       3: "dot11_BSS_type_any"}

# The DOT11_MAC_ADDRESS types are used to define an IEEE media access control
# (MAC) address.
DOT11_MAC_ADDRESS = c_ubyte * 6

# The DOT11_BSS_TYPE enumerated type defines a basic service set (BSS) network
# type.
DOT11_BSS_TYPE = c_uint
DOT11_BSS_TYPE_DICT = {1: "dot11_BSS_type_infrastructure",
                       2: "dot11_BSS_type_independent",
                       3: "dot11_BSS_type_any"}

# The DOT11_PHY_TYPE enumeration defines an 802.11 PHY and media type.
DOT11_PHY_TYPE = c_uint
DOT11_PHY_TYPE_DICT = {0: "dot11_phy_type_unknown",
                       1: "dot11_phy_type_fhss",
                       2: "dot11_phy_type_dsss",
                       3: "dot11_phy_type_irbaseband",
                       4: "dot11_phy_type_ofdm",
                       5: "dot11_phy_type_hrdsss",
                       6: "dot11_phy_type_erp",
                       7: "dot11_phy_type_ht",
                       0x80000000: "dot11_phy_type_IHV_start",
                       0xffffffff: "dot11_phy_type_IHV_end"}

DOT11_RATE_SET_MAX_LENGTH = 126

WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES = 0x00000001
WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES = 0x00000002


class WLAN_INTERFACE_INFO(Structure):
    """
        The WLAN_INTERFACE_INFO structure contains information about a wireless
        LAN interface.

        typedef struct _WLAN_INTERFACE_INFO {
            GUID                 InterfaceGuid;
            WCHAR                strInterfaceDescription[256];
            WLAN_INTERFACE_STATE isState;
        } WLAN_INTERFACE_INFO, *PWLAN_INTERFACE_INFO;
    """
    _fields_ = [("InterfaceGuid", GUID),
                ("strInterfaceDescription", c_wchar * 256),
                ("isState", WLAN_INTERFACE_STATE)]


class WLAN_INTERFACE_INFO_LIST(Structure):
    """
        The WLAN_INTERFACE_INFO_LIST structure contains an array of NIC
        interface information.

        typedef struct _WLAN_INTERFACE_INFO_LIST {
            DWORD               dwNumberOfItems;
            DWORD               dwIndex;
            WLAN_INTERFACE_INFO InterfaceInfo[];
        } WLAN_INTERFACE_INFO_LIST, *PWLAN_INTERFACE_INFO_LIST;
    """
    _fields_ = [("NumberOfItems", DWORD),
                ("Index", DWORD),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]


class DOT11_SSID(Structure):
    """
        A DOT11_SSID structure contains the SSID of an interface.

        typedef struct _DOT11_SSID {
            ULONG uSSIDLength;
            UCHAR ucSSID[DOT11_SSID_MAX_LENGTH];
        } DOT11_SSID, *PDOT11_SSID;
    """
    _fields_ = [("SSIDLength", c_ulong),
                ("SSID", c_char * DOT11_SSID_MAX_LENGTH)]


class WLAN_RAW_DATA(Structure):
    """
        The WLAN_RAW_DATA structure contains raw data in the form of a blob
        that is used by some Native Wifi functions.

        typedef struct _WLAN_RAW_DATA {
            DWORD dwDataSize;
            BYTE  DataBlob[1];
        } WLAN_RAW_DATA, *PWLAN_RAW_DATA;
    """
    _fields_ = [("DataSize", DWORD),
                ("DataBlob", c_byte * 1)]


class WLAN_RATE_SET(Structure):
    """
        typedef struct _WLAN_RATE_SET {
            ULONG  uRateSetLength;
            USHORT usRateSet[DOT11_RATE_SET_MAX_LENGTH];
        } WLAN_RATE_SET, *PWLAN_RATE_SET;
    """
    _fields_ = [("RateSetLength", c_ulong),
                ("RateSet", c_ushort * DOT11_RATE_SET_MAX_LENGTH)]


class WLAN_BSS_ENTRY(Structure):
    """
        The WLAN_BSS_ENTRY structure contains information about a basic service
        set (BSS).

        typedef struct _WLAN_BSS_ENTRY {
            DOT11_SSID        dot11Ssid;
            ULONG             uPhyId;
            DOT11_MAC_ADDRESS dot11Bssid;
            DOT11_BSS_TYPE    dot11BssType;
            DOT11_PHY_TYPE    dot11BssPhyType;
            LONG              lRssi;
            ULONG             uLinkQuality;
            BOOLEAN           bInRegDomain;
            USHORT            usBeaconPeriod;
            ULONGLONG         ullTimestamp;
            ULONGLONG         ullHostTimestamp;
            USHORT            usCapabilityInformation;
            ULONG             ulChCenterFrequency;
            WLAN_RATE_SET     wlanRateSet;
            ULONG             ulIeOffset;
            ULONG             ulIeSize;
        } WLAN_BSS_ENTRY, *PWLAN_BSS_ENTRY;
    """
    _fields_ = [("dot11Ssid", DOT11_SSID),
                ("PhyId", c_ulong),
                ("dot11Bssid", DOT11_MAC_ADDRESS),
                ("dot11BssType", DOT11_BSS_TYPE),
                ("dot11BssPhyType", DOT11_PHY_TYPE),
                ("Rssi", c_long),
                ("LinkQuality", c_ulong),
                ("InRegDomain", BOOL),
                ("BeaconPeriod", c_ushort),
                ("Timestamp", c_ulonglong),
                ("HostTimestamp", c_ulonglong),
                ("CapabilityInformation", c_ushort),
                ("ChCenterFrequency", c_ulong),
                ("wlanRateSet", WLAN_RATE_SET),
                ("IeOffset", c_ulong),
                ("IeSize", c_ulong)]


class WLAN_BSS_LIST(Structure):
    """
        The WLAN_BSS_LIST structure contains a list of basic service set (BSS)
        entries.

        typedef struct _WLAN_BSS_LIST {
            DWORD          dwTotalSize;
            DWORD          dwNumberOfItems;
            WLAN_BSS_ENTRY wlanBssEntries[1];
        } WLAN_BSS_LIST, *PWLAN_BSS_LIST;
    """
    _fields_ = [("TotalSize", DWORD),
                ("NumberOfItems", DWORD),
                ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]


def WlanOpenHandle():
    """
        The WlanOpenHandle function opens a connection to the server.

        DWORD WINAPI WlanOpenHandle(
            _In_        DWORD dwClientVersion,
            _Reserved_  PVOID pReserved,
            _Out_       PDWORD pdwNegotiatedVersion,
            _Out_       PHANDLE phClientHandle
        );
    """
    func_ref = wlanapi.WlanOpenHandle
    func_ref.argtypes = [DWORD, c_void_p, POINTER(DWORD), POINTER(HANDLE)]
    func_ref.restype = DWORD
    negotiated_version = DWORD()
    client_handle = HANDLE()
    result = func_ref(2, None, byref(negotiated_version), byref(client_handle))
    if result != ERROR_SUCCESS:
        raise Exception("WlanOpenHandle failed.")
    return client_handle


def WlanCloseHandle(hClientHandle):
    """
        The WlanCloseHandle function closes a connection to the server.

        DWORD WINAPI WlanCloseHandle(
            _In_        HANDLE hClientHandle,
            _Reserved_  PVOID pReserved
        );
    """
    func_ref = wlanapi.WlanCloseHandle
    func_ref.argtypes = [HANDLE, c_void_p]
    func_ref.restype = DWORD
    result = func_ref(hClientHandle, None)
    if result != ERROR_SUCCESS:
        raise Exception("WlanCloseHandle failed.")
    return result


def WlanFreeMemory(pMemory):
    """
        The WlanFreeMemory function frees memory. Any memory returned from
        Native Wifi functions must be freed.

        VOID WINAPI WlanFreeMemory(
            _In_  PVOID pMemory
        );
    """
    func_ref = wlanapi.WlanFreeMemory
    func_ref.argtypes = [c_void_p]
    func_ref(pMemory)


def WlanEnumInterfaces(hClientHandle):
    """
        The WlanEnumInterfaces function enumerates all of the wireless LAN
        interfaces currently enabled on the local computer.

        DWORD WINAPI WlanEnumInterfaces(
            _In_        HANDLE hClientHandle,
            _Reserved_  PVOID pReserved,
            _Out_       PWLAN_INTERFACE_INFO_LIST *ppInterfaceList
        );
    """
    func_ref = wlanapi.WlanEnumInterfaces
    func_ref.argtypes = [HANDLE,
                         c_void_p,
                         POINTER(POINTER(WLAN_INTERFACE_INFO_LIST))]
    func_ref.restype = DWORD
    wlan_ifaces = pointer(WLAN_INTERFACE_INFO_LIST())
    result = func_ref(hClientHandle, None, byref(wlan_ifaces))
    if result != ERROR_SUCCESS:
        raise Exception("WlanEnumInterfaces failed.")
    return wlan_ifaces


def WlanScan(hClientHandle, pInterfaceGuid, ssid=""):
    """
        The WlanScan function requests a scan for available networks on the
        indicated interface.

        DWORD WINAPI WlanScan(
            _In_        HANDLE hClientHandle,
            _In_        const GUID *pInterfaceGuid,
            _In_opt_    const PDOT11_SSID pDot11Ssid,
            _In_opt_    const PWLAN_RAW_DATA pIeData,
            _Reserved_  PVOID pReserved
        );
    """
    func_ref = wlanapi.WlanScan
    func_ref.argtypes = [HANDLE,
                         POINTER(GUID),
                         POINTER(DOT11_SSID),
                         POINTER(WLAN_RAW_DATA),
                         c_void_p]
    func_ref.restype = DWORD
    if ssid:
        length = len(ssid)
        if length > DOT11_SSID_MAX_LENGTH:
            raise Exception("SSIDs have a maximum length of 32 characters.")
        # data = tuple(ord(char) for char in ssid)
        data = ssid
        dot11_ssid = byref(DOT11_SSID(length, data))
    else:
        dot11_ssid = None
    # TODO: Support WLAN_RAW_DATA argument.
    result = func_ref(hClientHandle,
                      byref(pInterfaceGuid),
                      dot11_ssid,
                      None,
                      None)
    if result != ERROR_SUCCESS:
        raise Exception("WlanScan failed.")
    return result


def WlanGetNetworkBssList(hClientHandle, pInterfaceGuid):
    """
        The WlanGetNetworkBssList function retrieves a list of the basic
        service set (BSS) entries of the wireless network or networks on a
        given wireless LAN interface.

        DWORD WINAPI WlanGetNetworkBssList(
            _In_        HANDLE hClientHandle,
            _In_        const GUID *pInterfaceGuid,
            _In_        const  PDOT11_SSID pDot11Ssid,
            _In_        DOT11_BSS_TYPE dot11BssType,
            _In_        BOOL bSecurityEnabled,
            _Reserved_  PVOID pReserved,
            _Out_       PWLAN_BSS_LIST *ppWlanBssList
        );
    """
    func_ref = wlanapi.WlanGetNetworkBssList
    # TODO: handle the arguments descibed below.
    # pDot11Ssid - When set to NULL, the returned list contains all of
    # available BSS entries on a wireless LAN interface.
    # dot11BssType - The BSS type of the network. This parameter is ignored if
    # the SSID of the network for the BSS list is unspecified (the pDot11Ssid
    # parameter is NULL).
    # bSecurityEnabled - A value that indicates whether security is enabled on
    # the network. This parameter is only valid when the SSID of the network
    # for the BSS list is specified (the pDot11Ssid parameter is not NULL).
    func_ref.argtypes = [HANDLE,
                         POINTER(GUID),
                         c_void_p,
                         c_void_p,
                         c_void_p,
                         c_void_p,
                         POINTER(POINTER(WLAN_BSS_LIST))]
    func_ref.restype = DWORD
    wlan_bss_list = pointer(WLAN_BSS_LIST())
    result = func_ref(hClientHandle,
                      byref(pInterfaceGuid),
                      None,
                      None,
                      None,
                      None,
                      byref(wlan_bss_list))
    if result != ERROR_SUCCESS:
        raise Exception("WlanGetNetworkBssList failed.")
    return wlan_bss_list
