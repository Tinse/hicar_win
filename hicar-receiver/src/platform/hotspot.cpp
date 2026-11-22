#include "platform/hotspot.h"

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <wlanapi.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Networking.Connectivity.h>
#include <winrt/Windows.Networking.NetworkOperators.h>

namespace hicar {
namespace platform {
namespace {

using winrt::Windows::Networking::Connectivity::NetworkInformation;
using winrt::Windows::Networking::Connectivity::NetworkConnectivityLevel;
using winrt::Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration;
using winrt::Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager;
using winrt::Windows::Networking::NetworkOperators::TetheringWiFiBand;
using winrt::Windows::Networking::NetworkOperators::TetheringOperationalState;
using winrt::Windows::Networking::NetworkOperators::TetheringOperationStatus;

NetworkOperatorTetheringManager g_manager{nullptr};
bool g_apartment = false;
bool g_owned = false;

std::string read_hotspot_bssid(const std::string& ssid) {
  HANDLE handle = nullptr;
  DWORD negotiated = 0;
  if (WlanOpenHandle(2, nullptr, &negotiated, &handle) != ERROR_SUCCESS) return {};

  std::string bssid;
  PWLAN_INTERFACE_INFO_LIST interfaces = nullptr;
  if (WlanEnumInterfaces(handle, nullptr, &interfaces) == ERROR_SUCCESS && interfaces != nullptr) {
    for (DWORD i = 0; i < interfaces->dwNumberOfItems && bssid.empty(); ++i) {
      DOT11_SSID filter{};
      const size_t length = ssid.size() > 32 ? 32 : ssid.size();
      filter.uSSIDLength = static_cast<ULONG>(length);
      std::memcpy(filter.ucSSID, ssid.data(), length);

      PWLAN_BSS_LIST list = nullptr;
      const DWORD result = WlanGetNetworkBssList(handle, &interfaces->InterfaceInfo[i].InterfaceGuid,
                                                 &filter, dot11_BSS_type_infrastructure, FALSE, nullptr,
                                                 &list);
      if (result == ERROR_SUCCESS && list != nullptr) {
        for (DWORD j = 0; j < list->dwNumberOfItems; ++j) {
          const WLAN_BSS_ENTRY& entry = list->wlanBssEntries[j];
          char text[18];
          std::snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
                        entry.dot11Bssid[0], entry.dot11Bssid[1], entry.dot11Bssid[2],
                        entry.dot11Bssid[3], entry.dot11Bssid[4], entry.dot11Bssid[5]);
          bssid = text;
          break;
        }
        WlanFreeMemory(list);
      }
    }
    WlanFreeMemory(interfaces);
  }
  WlanCloseHandle(handle, nullptr);
  return bssid;
}

uint32_t read_hotspot_frequency(const std::string& ssid) {
  HANDLE handle = nullptr;
  DWORD negotiated = 0;
  if (WlanOpenHandle(2, nullptr, &negotiated, &handle) != ERROR_SUCCESS) return 0;

  uint32_t frequency = 0;
  PWLAN_INTERFACE_INFO_LIST interfaces = nullptr;
  if (WlanEnumInterfaces(handle, nullptr, &interfaces) == ERROR_SUCCESS && interfaces != nullptr) {
    for (DWORD i = 0; i < interfaces->dwNumberOfItems && frequency == 0; ++i) {
      DOT11_SSID filter{};
      const size_t length = ssid.size() > 32 ? 32 : ssid.size();
      filter.uSSIDLength = static_cast<ULONG>(length);
      std::memcpy(filter.ucSSID, ssid.data(), length);

      PWLAN_BSS_LIST list = nullptr;
      const DWORD result = WlanGetNetworkBssList(handle, &interfaces->InterfaceInfo[i].InterfaceGuid,
                                                 &filter, dot11_BSS_type_infrastructure, FALSE, nullptr,
                                                 &list);
      if (result == ERROR_SUCCESS && list != nullptr) {
        for (DWORD j = 0; j < list->dwNumberOfItems; ++j) {
          frequency = list->wlanBssEntries[j].ulChCenterFrequency;
          if (frequency != 0) break;
        }
        WlanFreeMemory(list);
      }
    }
    WlanFreeMemory(interfaces);
  }
  WlanCloseHandle(handle, nullptr);
  return frequency;
}

struct AdapterAddress {
  std::string ip;
  std::string mac;
  std::string name;
};

AdapterAddress find_ics_adapter() {
  AdapterAddress found;
  ULONG size = 0;
  const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
  if (GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW || size == 0) {
    return found;
  }
  auto* addresses = static_cast<IP_ADAPTER_ADDRESSES*>(std::malloc(size));
  if (addresses == nullptr) return found;
  if (GetAdaptersAddresses(AF_INET, flags, nullptr, addresses, &size) == ERROR_SUCCESS) {
    for (auto* adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
      for (auto* unicast = adapter->FirstUnicastAddress; unicast != nullptr; unicast = unicast->Next) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(unicast->Address.lpSockaddr);
        if (ipv4 == nullptr || ipv4->sin_family != AF_INET) continue;
        char text[INET_ADDRSTRLEN] = {};
        const uint32_t address = ntohl(ipv4->sin_addr.s_addr);
        std::snprintf(text, sizeof(text), "%u.%u.%u.%u", (address >> 24) & 0xFFu,
                      (address >> 16) & 0xFFu, (address >> 8) & 0xFFu, address & 0xFFu);
        if (std::strcmp(text, "192.168.137.1") != 0) continue;

        found.ip = text;
        found.name = adapter->AdapterName != nullptr ? adapter->AdapterName : "";
        if (adapter->PhysicalAddressLength >= 6) {
          const auto* mac = adapter->PhysicalAddress;
          char mac_text[18];
          std::snprintf(mac_text, sizeof(mac_text), "%02x:%02x:%02x:%02x:%02x:%02x",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
          found.mac = mac_text;
        }
        std::free(addresses);
        return found;
      }
    }
  }
  std::free(addresses);
  return found;
}

}  // namespace

bool start_hotspot(const HotspotConfig& config, HotspotInfo* info, std::string* error) {
  if (error != nullptr) error->clear();
  if (info == nullptr) return false;
  if (config.ssid.empty() || config.passphrase.size() < 8) {
    if (error != nullptr) *error = "SSID 为空或密码少于 8 个字符";
    return false;
  }

  try {
    if (!g_apartment) {
      winrt::init_apartment(winrt::apartment_type::multi_threaded);
      g_apartment = true;
    }

    auto profile = NetworkInformation::GetInternetConnectionProfile();
    if (!profile) {
      for (const auto& candidate : NetworkInformation::GetConnectionProfiles()) {
        if (candidate.GetNetworkConnectivityLevel() == NetworkConnectivityLevel::InternetAccess) {
          profile = candidate;
          break;
        }
      }
    }
    if (!profile) {
      if (error != nullptr) *error = "没有可用的 Internet 连接（ICS 上游）";
      return false;
    }

    auto manager = NetworkOperatorTetheringManager::CreateFromConnectionProfile(profile);
    if (!manager) {
      if (error != nullptr) *error = "创建热点管理器失败";
      return false;
    }

    const auto state = manager.TetheringOperationalState();
    if (state == TetheringOperationalState::On) {
      if (error != nullptr) *error = "热点已在运行（不是本进程启动，不会接管）";
      return false;
    }

    auto access_point = manager.GetCurrentAccessPointConfiguration();
    access_point.Ssid(winrt::to_hstring(config.ssid));
    access_point.Passphrase(winrt::to_hstring(config.passphrase));
    // 优先 2.4G：兼容性最好；不支持时保持系统默认。
    try {
      if (access_point.IsBandSupported(TetheringWiFiBand::TwoPointFourGigahertz)) {
        access_point.Band(TetheringWiFiBand::TwoPointFourGigahertz);
      }
    } catch (...) {
    }
    auto configure = manager.ConfigureAccessPointAsync(access_point);
    if (configure.wait_for(std::chrono::seconds(8)) !=
        winrt::Windows::Foundation::AsyncStatus::Completed) {
      if (error != nullptr) *error = "配置热点超时（系统未响应）";
      return false;
    }
    configure.get();

    auto start = manager.StartTetheringAsync();
    if (start.wait_for(std::chrono::seconds(15)) !=
        winrt::Windows::Foundation::AsyncStatus::Completed) {
      if (error != nullptr) *error = "启动热点超时（系统未响应）";
      return false;
    }
    const auto result = start.get();
    if (result.Status() != TetheringOperationStatus::Success) {
      if (error != nullptr) {
        *error = "启动热点失败：" + winrt::to_string(result.AdditionalErrorMessage());
      }
      return false;
    }
    g_manager = manager;
    g_owned = true;

    std::this_thread::sleep_for(std::chrono::milliseconds(2500));

    const auto current = manager.GetCurrentAccessPointConfiguration();
    info->ssid = winrt::to_string(current.Ssid());
    info->passphrase = winrt::to_string(current.Passphrase());

    const auto ics = find_ics_adapter();
    info->car_ip = ics.ip.empty() ? "192.168.137.1" : ics.ip;
    info->adapter_name = ics.name;

    std::string bssid;
    for (int attempt = 0; attempt < 12; ++attempt) {
      bssid = read_hotspot_bssid(info->ssid);
      info->frequency_mhz = read_hotspot_frequency(info->ssid);
      if (!bssid.empty() && info->frequency_mhz != 0) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    info->bssid = bssid.empty() ? ics.mac : bssid;
    if (info->frequency_mhz == 0) {
      try {
        const auto band = current.Band();
        info->frequency_mhz =
            band == TetheringWiFiBand::FiveGigahertz ? 5745u : 2437u;
      } catch (...) {
        info->frequency_mhz = 2437;
      }
    }
    return true;
  } catch (const winrt::hresult_error& e) {
    if (error != nullptr) {
      *error = "WinRT 异常 0x" + std::to_string(static_cast<unsigned int>(e.code())) + "：" +
               winrt::to_string(e.message());
    }
    return false;
  } catch (const std::exception& e) {
    if (error != nullptr) *error = std::string("异常：") + e.what();
    return false;
  }
}

bool stop_hotspot(std::string* error) {
  if (error != nullptr) error->clear();
  if (!g_owned || !g_manager) return true;
  try {
    const auto result = g_manager.StopTetheringAsync().get();
    g_owned = false;
    g_manager = nullptr;
    if (result.Status() != TetheringOperationStatus::Success) {
      if (error != nullptr) {
        *error = "停止热点失败：" + winrt::to_string(result.AdditionalErrorMessage());
      }
      return false;
    }
    return true;
  } catch (const winrt::hresult_error& e) {
    if (error != nullptr) *error = "停止热点异常：" + winrt::to_string(e.message());
    return false;
  }
}

}  // namespace platform
}  // namespace hicar
