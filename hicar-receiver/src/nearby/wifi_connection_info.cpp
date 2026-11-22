#include "nearby/wifi_connection_info.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <stdexcept>

#include "common/error.h"

namespace hicar {

namespace {

const std::string kSeparator = "##";

bool is_canonical_ipv4(const std::string& text) {
  int parts = 0;
  size_t start = 0;
  while (true) {
    const size_t dot = text.find('.', start);
    const std::string piece = text.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
    if (piece.empty() || piece.size() > 3) return false;
    if (piece.size() > 1 && piece[0] == '0') return false;
    for (char c : piece) {
      if (c < '0' || c > '9') return false;
    }
    if (std::stoi(piece) > 255) return false;
    ++parts;
    if (dot == std::string::npos) break;
    start = dot + 1;
  }
  return parts == 4;
}

bool is_mac(const std::string& text) {
  if (text.size() != 17) return false;
  for (size_t i = 0; i < 17; ++i) {
    if (i % 3 == 2) {
      if (text[i] != ':') return false;
    } else {
      const char c = text[i];
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    }
  }
  return true;
}

bool is_wpa2_passphrase(const std::string& text) {
  const bool printable = text.size() >= 8 && text.size() <= 63;
  if (printable) {
    for (char c : text) {
      if (c < ' ' || c > '~') return false;
    }
    return true;
  }
  if (text.size() == 64) {
    return std::all_of(text.begin(), text.end(), [](char c) {
      return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    });
  }
  return false;
}

std::vector<std::string> split(const std::string& text, const std::string& separator) {
  std::vector<std::string> out;
  size_t start = 0;
  while (true) {
    const size_t at = text.find(separator, start);
    out.push_back(text.substr(start, at == std::string::npos ? std::string::npos : at - start));
    if (at == std::string::npos) break;
    start = at + separator.size();
  }
  return out;
}

uint32_t parse_uint(const std::string& text, const char* what) {
  if (text.empty() || text.size() > 9) throw MalformedMessage(std::string(what) + " 不是十进制数");
  for (char c : text) {
    if (c < '0' || c > '9') throw MalformedMessage(std::string(what) + " 不是十进制数");
  }
  return static_cast<uint32_t>(std::stoul(text));
}

}  // namespace

std::optional<uint32_t> channel_of_frequency(uint32_t frequency_mhz) {
  if (frequency_mhz == 2484) return 14;
  if (frequency_mhz >= 2400 && frequency_mhz <= 2484) return (frequency_mhz - 2407) / 5;
  if (frequency_mhz >= 4900 && frequency_mhz <= 5900) return (frequency_mhz - 5000) / 5;
  return std::nullopt;
}

std::optional<uint32_t> frequency_of_channel(uint32_t channel) {
  if (channel == 14) return 2484;
  if (channel >= 1 && channel <= 13) return 2407 + channel * 5;
  if (channel >= 32 && channel <= 177) return 5000 + channel * 5;
  return std::nullopt;
}

std::optional<uint32_t> WifiConnectionInfo::channel() const { return channel_of_frequency(frequency_mhz); }

std::string WifiConnectionInfo::encode() const {
  if (!is_canonical_ipv4(phone_ip)) throw std::invalid_argument("手机 IP 不是 IPv4 地址");
  if (!is_canonical_ipv4(car_ip)) throw std::invalid_argument("车机 IP 不是 IPv4 地址");
  if (phone_ip == car_ip) throw std::invalid_argument("手机 IP 不能和车机 IP 相同");
  if (ssid.empty()) throw std::invalid_argument("网络名不能为空");
  for (char c : ssid) {
    if (static_cast<unsigned char>(c) < 0x20 || c == 0x7F) throw std::invalid_argument("网络名不能含控制字符");
  }
  if (ssid.find(kSeparator) != std::string::npos) throw std::invalid_argument("网络名不能含 ##");
  if (!is_mac(bssid)) throw std::invalid_argument("BSSID 应为 aa:bb:cc:dd:ee:ff");
  if (!is_wpa2_passphrase(passphrase)) throw std::invalid_argument("密码格式不合法");
  if (passphrase.find(kSeparator) != std::string::npos) throw std::invalid_argument("密码不能含 ##");
  if (!channel_of_frequency(frequency_mhz).has_value()) throw std::invalid_argument("频率不是 WiFi 信道");
  if (port == 0) throw std::invalid_argument("端口不能为 0");

  std::string ssid_text;
  for (char c : ssid) {
    if (c == '\\') ssid_text += "\\\\";
    else ssid_text.push_back(c);
  }

  std::string out = phone_ip + kSeparator + ssid_text + "\n" + bssid + "\n" + passphrase + "\n" +
                    std::to_string(frequency_mhz);
  if (mode == WifiMode::kHotspot) out += "\n1";
  out += kSeparator + std::string("version:") + std::to_string(kVersion);
  out += kSeparator + std::to_string(port);
  if (mode == WifiMode::kHotspot) out += kSeparator + std::to_string(*channel());
  out += kSeparator + "hicarApIp:" + car_ip;
  return out;
}

WifiConnectionInfo WifiConnectionInfo::parse(const std::string& text) {
  const std::vector<std::string> parts = split(text, kSeparator);
  WifiConnectionInfo out;
  if (parts.size() == 6) {
    out.mode = WifiMode::kHotspot;
  } else if (parts.size() == 5) {
    out.mode = WifiMode::kDirect;
  } else {
    throw MalformedMessage("连接串应有 5 段（直连）或 6 段（热点）");
  }
  const std::vector<std::string> lines = split(parts[1], "\n");
  const size_t expected = out.mode == WifiMode::kHotspot ? 5 : 4;
  if (lines.size() != expected) throw MalformedMessage("网络段行数不对");
  if (out.mode == WifiMode::kHotspot && lines[4] != "1") throw MalformedMessage("热点格式缺少加入标记");

  out.phone_ip = parts[0];
  out.ssid.clear();
  for (size_t i = 0; i < lines[0].size(); ++i) {
    if (lines[0][i] == '\\') {
      if (i + 1 >= lines[0].size() || lines[0][i + 1] != '\\') throw MalformedMessage("网络名里有落单的反斜杠");
      ++i;
    }
    out.ssid.push_back(lines[0][i]);
  }
  out.bssid = lines[1];
  std::transform(out.bssid.begin(), out.bssid.end(), out.bssid.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  out.passphrase = lines[2];
  out.frequency_mhz = parse_uint(lines[3], "频率");
  if (parts[2] != std::string("version:") + std::to_string(kVersion)) throw MalformedMessage("不支持的版本");
  out.port = static_cast<uint16_t>(parse_uint(parts[3], "端口"));
  if (out.mode == WifiMode::kHotspot) {
    const uint32_t channel = parse_uint(parts[4], "信道号");
    if (!out.channel().has_value() || *out.channel() != channel) throw MalformedMessage("信道号和频率对不上");
  }
  const std::string last = parts.back();
  if (last.rfind("hicarApIp:", 0) != 0) throw MalformedMessage("连接串末段不是车机地址");
  out.car_ip = last.substr(std::string("hicarApIp:").size());
  return out;
}

std::string pick_phone_address(const std::string& car_ip, const std::vector<std::string>& taken) {
  if (!is_canonical_ipv4(car_ip)) throw std::invalid_argument("车机 IP 不是 IPv4 地址");
  const size_t dot = car_ip.rfind('.');
  const std::string prefix = car_ip.substr(0, dot + 1);
  for (uint32_t host = 2; host <= 100; ++host) {
    const std::string candidate = prefix + std::to_string(host);
    if (candidate == car_ip) continue;
    if (std::find(taken.begin(), taken.end(), candidate) != taken.end()) continue;
    return candidate;
  }
  throw std::runtime_error("网段里 .2～.100 都被占了");
}

}  // namespace hicar
