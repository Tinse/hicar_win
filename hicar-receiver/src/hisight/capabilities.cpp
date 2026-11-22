#include "hisight/capabilities.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <set>
#include <sstream>
#include <stdexcept>

namespace hicar {
namespace hisight {
namespace {

void fail(const std::string& message) { throw std::runtime_error(message); }

std::vector<std::string> split(const std::string& text, char delimiter) {
  std::vector<std::string> parts;
  size_t start = 0;
  while (true) {
    const size_t at = text.find(delimiter, start);
    if (at == std::string::npos) {
      parts.push_back(text.substr(start));
      break;
    }
    parts.push_back(text.substr(start, at - start));
    start = at + 1;
  }
  return parts;
}

std::vector<std::string> split_spaces(const std::string& text) {
  std::vector<std::string> tokens;
  size_t i = 0;
  while (i < text.size()) {
    while (i < text.size() && (text[i] == ' ' || text[i] == '\t')) ++i;
    if (i >= text.size()) break;
    size_t begin = i;
    while (i < text.size() && text[i] != ' ' && text[i] != '\t') ++i;
    tokens.push_back(text.substr(begin, i - begin));
  }
  return tokens;
}

std::map<std::string, int> integer_fields(const std::string& value, const std::set<std::string>& known,
                                          const std::set<std::string>& lenient = {}) {
  std::map<std::string, int> result;
  std::vector<std::string> parts = split(value, ';');
  if (!parts.empty() && parts.back().empty()) parts.pop_back();
  for (const std::string& part : parts) {
    const std::vector<std::string> tokens = split_spaces(trim_space_tab(part));
    if (tokens.empty()) fail("参数子字段为空");
    const std::string& name = tokens[0];
    if (lenient.count(name) != 0) {
      if (tokens.size() == 2) {
        const long long number = parse_decimal(tokens[1], 10);
        if (number >= 0 && number <= 2147483647LL && result.count(name) == 0) {
          result[name] = static_cast<int>(number);
        }
      }
      continue;
    }
    if (tokens.size() != 2 || known.count(name) == 0 || result.count(name) != 0) {
      fail("参数子字段未知、重复或格式错误");
    }
    const long long number = parse_decimal(tokens[1], 10);
    if (number < 0 || number > 2147483647LL) fail("参数子字段不是有效非负整数");
    result[name] = static_cast<int>(number);
  }
  return result;
}

}  // namespace

const std::vector<std::string>& Capabilities::touch_events() {
  static const std::vector<std::string> events = {"left_point_down", "left_point_up", "left_move"};
  return events;
}

const std::vector<std::string>& Capabilities::key_events() {
  static const std::vector<std::string> events = {"left_key_down", "left_key_up"};
  return events;
}

const std::string& Capabilities::text_vendor() {
  static const std::string vendor = "input_content";
  return vendor;
}

Capabilities::Capabilities(const HisightConfig& config) : config_(config) {
  if (config_.touch_input) {
    for (const auto& event : touch_events()) advertised_events_.push_back(event);
  }
  if (config_.key_input || config_.media_key_input) {
    for (const auto& event : key_events()) advertised_events_.push_back(event);
  }
  if (config_.media_key_input && !config_.key_input) {
    for (const auto& event : key_events()) optional_events_.insert(event);
  }
  for (const auto& event : advertised_events_) {
    if (optional_events_.count(event) == 0) required_events_.insert(event);
  }
  if (config_.text_input) advertised_vendors_.push_back(text_vendor());
}

std::string Capabilities::response_body(const std::vector<uint8_t>& query) const {
  std::map<std::string, std::string> supported;
  supported["his_version"] = "1.1";
  std::string formats = "codecs 1";
  formats += ";fps " + std::to_string(config_.fps);
  if (config_.gop.has_value()) formats += ";gop " + std::to_string(*config_.gop);
  if (config_.bitrate.has_value()) formats += ";bitrate " + std::to_string(*config_.bitrate);
  formats += ";dpi " + std::to_string(config_.dpi);
  formats += ";scr-w " + std::to_string(config_.screen_width);
  formats += ";scr-h " + std::to_string(config_.screen_height);
  formats += ";width " + std::to_string(config_.video_width);
  formats += ";height " + std::to_string(config_.video_height);
  supported["his_video_formats"] = formats;
  supported["his_feature"] = "input_feature_set=;";
  supported["his_device_type"] = "device_type " + std::to_string(config_.device_type) + ";subtype 0;";
  if (!advertised_events_.empty()) {
    std::string value = "input_category_list=GENERIC;generic_cap_list=";
    for (size_t i = 0; i < advertised_events_.size(); ++i) {
      if (i != 0) value += ", ";
      value += advertised_events_[i];
    }
    value += ";";
    if (!advertised_vendors_.empty()) {
      value += "vendor_cap_list=";
      for (size_t i = 0; i < advertised_vendors_.size(); ++i) {
        if (i != 0) value += ", ";
        value += advertised_vendors_[i];
      }
      value += ";";
    }
    supported["his_uibc_capability"] = value;
  }

  std::string out;
  for (const std::string& name : query_names(query)) {
    const auto it = supported.find(name);
    if (it != supported.end()) out += name + ": " + it->second + "\r\n";
  }
  return out;
}

void Capabilities::select(const std::map<std::string, std::string>& fields) {
  static const std::set<std::string> capability_fields = {
      "his_version", "his_video_formats", "his_audio_codecs", "his_uibc_capability",
      "his_vtp", "his_feature", "his_device_type", "his_media_capability",
  };
  static const std::set<std::string> metadata_fields = {
      "his_audio_formats", "his_support_uwb", "his_support_temp_notify", "his_presentation_url",
      "his_extended_field", "his_player_controller_capability",
  };
  if (fields.empty()) fail("能力选择为空");
  for (const auto& item : fields) {
    if (capability_fields.count(item.first) == 0 && metadata_fields.count(item.first) == 0) {
      fail("能力选择含未实现字段");
    }
  }
  const auto version = fields.find("his_version");
  if (version != fields.end() && !accepted_version(version->second)) fail("手机版本不是 1.0 或 1.1");
  const auto audio = fields.find("his_audio_codecs");
  if (audio != fields.end()) {
    std::string value = audio->second;
    for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (value != "none") fail("手机选择了未声明的音频能力");
  }

  std::vector<std::string> events = input_events_;
  std::vector<std::string> vendors = input_vendors_;
  const auto uibc = fields.find("his_uibc_capability");
  if (!advertised_events_.empty()) {
    const bool optional_only = required_events_.empty() && advertised_vendors_.empty();
    std::string value = uibc == fields.end() ? "" : uibc->second;
    for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (uibc == fields.end() || (optional_only && value == "none")) {
      if (!optional_only) fail("手机没有选择已声明的输入能力");
      events.clear();
      vendors.clear();
    } else {
      const auto picked = input_selection(uibc->second);
      events = picked.first;
      vendors = picked.second;    }
  } else if (uibc != fields.end()) {
    std::string value = uibc->second;
    for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (value != "none") fail("手机选择了未声明的输入能力");
  }
  const auto media = fields.find("his_media_capability");
  if (media != fields.end()) {
    std::string value = media->second;
    for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (!value.empty() && value != "none") fail("手机选择了未声明的扩展媒体能力");
  }
  if (fields.count("his_vtp") != 0) fail("没有声明 VTP，手机却选择了它");
  const auto feature = fields.find("his_feature");
  if (feature != fields.end() && feature->second != "input_feature_set=;") {
    fail("手机选择了未实现的输入功能");
  }

  std::optional<int> source = source_device_type_;
  const auto device_value = fields.find("his_device_type");
  if (config_.device_type == 5 && device_value == fields.end()) fail("手机没有选回接收端类型 5");
  if (device_value != fields.end()) {
    const auto parsed = integer_fields(device_value->second,
                                       {"device_type", "subtype", "source_device_type", "source_subtype"});
    const int type = parsed.count("device_type") != 0 ? parsed.at("device_type") : 4;
    const int subtype = parsed.count("subtype") != 0 ? parsed.at("subtype") : 0;
    if (type != config_.device_type || subtype != 0) fail("手机选择的接收端类型与声明不符");
    const auto it = parsed.find("source_device_type");
    if (it != parsed.end()) source = it->second;
  }
  if (config_.key_input && source.value_or(0) != 7) fail("按键输入要求手机明确选择 source_device_type 7");

  const auto formats = fields.find("his_video_formats");
  if (formats == fields.end()) {
    input_events_ = events;
    input_vendors_ = vendors;
    source_device_type_ = source;
    return;
  }
  const auto video = integer_fields(formats->second,
                                    {"codecs", "fps", "gop", "bitrate", "vbr-min", "vbr-max", "dpi",
                                     "scr-w", "scr-h", "width", "height", "color-standard"},
                                    {"gop", "bitrate"});
  const auto codec = video.find("codecs");
  const auto width = video.find("width");
  const auto height = video.find("height");
  const auto fps = video.find("fps");
  if (codec == video.end() || codec->second != 1 || width == video.end() || height == video.end() ||
      fps == video.end()) {
    fail("手机没有明确选择 H.264、尺寸和帧率");
  }
  if (width->second < 1 || width->second > config_.video_width || height->second < 1 ||
      height->second > config_.video_height || fps->second < 1 || fps->second > config_.fps) {
    fail("手机选择的尺寸或帧率超出声明范围");
  }
  selection_ = VideoSelection{width->second, height->second, fps->second};
  input_events_ = events;
  input_vendors_ = vendors;
  source_device_type_ = source;
}

MediaSetup Capabilities::media_setup(int video_port, int remote_control_port) const {
  if (!selection_.has_value()) fail("SETUP 前缺少视频参数选择");
  MediaSetup media;
  media.selection = *selection_;
  media.video_port = video_port;
  media.remote_control_port = remote_control_port;
  media.input_events = input_events_;
  media.input_vendors = input_vendors_;
  media.source_device_type = source_device_type_;

  if (!advertised_events_.empty()) {
    const std::set<std::string> picked(input_events_.begin(), input_events_.end());
    std::vector<std::string> picked_vendors = input_vendors_;
    std::sort(picked_vendors.begin(), picked_vendors.end());
    std::vector<std::string> declared = advertised_vendors_;
    std::sort(declared.begin(), declared.end());
    for (const auto& required : required_events_) {
      if (picked.count(required) == 0) fail("输入协商不完整");
    }
    for (const auto& event : picked) {
      if (std::find(advertised_events_.begin(), advertised_events_.end(), event) == advertised_events_.end()) {
        fail("输入协商含未声明事件");
      }
    }
    if (picked_vendors != declared) fail("vendor 输入协商不完整");
    const bool mandatory = !required_events_.empty() || !advertised_vendors_.empty();
    if (mandatory && (remote_control_port < 1 || remote_control_port > 65535)) {
      fail("手机没有给回控端口");
    }
    if (remote_control_port < 1 || remote_control_port > 65535) media.input_events.clear();
  }
  return media;
}

std::pair<std::vector<std::string>, std::vector<std::string>> Capabilities::input_selection(const std::string& text) const {
  std::vector<std::string> parts = split(text, ';');
  if (!parts.empty() && parts.back().empty()) parts.pop_back();
  std::map<std::string, std::string> fields;
  for (const auto& part : parts) {
    const size_t eq = part.find('=');
    if (eq == std::string::npos) fail("输入选择字段缺等号");
    const std::string name = part.substr(0, eq);
    if (name != "input_category_list" && name != "generic_cap_list" && name != "vendor_cap_list") {
      fail("输入选择含未知字段");
    }
    if (fields.count(name) != 0) fail("输入选择字段重复");
    fields[name] = part.substr(eq + 1);
  }
  const auto generic = fields.find("generic_cap_list");
  const auto category = fields.find("input_category_list");
  if (category == fields.end() || category->second != "GENERIC" || generic == fields.end()) {
    fail("输入选择必须是已声明的 GENERIC 类别");
  }
  std::vector<std::string> events;
  if (!generic->second.empty()) events = split(generic->second, ',');
  for (auto& event : events) event = trim_space_tab(event);
  std::set<std::string> unique(events.begin(), events.end());
  if (unique.size() != events.size()) fail("输入选择含重复事件");
  for (const auto& event : events) {
    if (std::find(advertised_events_.begin(), advertised_events_.end(), event) == advertised_events_.end()) {
      fail("输入选择含未声明事件");
    }
  }
  for (const auto& required : required_events_) {
    if (unique.count(required) == 0) fail("输入选择缺少已声明事件");
  }
  bool all_optional = true;
  for (const auto& optional : optional_events_) {
    if (unique.count(optional) == 0) all_optional = false;
  }
  if (!all_optional) {
    std::vector<std::string> filtered;
    for (const auto& event : events) {
      if (optional_events_.count(event) == 0) filtered.push_back(event);
    }
    events = filtered;
  }

  std::vector<std::string> vendors;
  const auto vendor = fields.find("vendor_cap_list");
  if (vendor != fields.end()) {
    vendors = split(vendor->second, ',');
    for (auto& item : vendors) item = trim_space_tab(item);
    std::set<std::string> unique_vendors(vendors.begin(), vendors.end());
    if (unique_vendors.size() != vendors.size()) fail("vendor 输入选择重复");
    for (const auto& item : vendors) {
      if (std::find(advertised_vendors_.begin(), advertised_vendors_.end(), item) == advertised_vendors_.end()) {
        fail("vendor 输入选择含未声明能力");
      }
    }
  }
  std::vector<std::string> a = vendors;
  std::vector<std::string> b = advertised_vendors_;
  std::sort(a.begin(), a.end());
  std::sort(b.begin(), b.end());
  if (a != b) fail("vendor 输入选择不完整");
  return {events, vendors};
}

bool Capabilities::accepted_version(const std::string& text) const {
  if (text.empty()) return false;
  size_t dot = text.find('.');
  const std::string integer = dot == std::string::npos ? text : text.substr(0, dot);
  const std::string fraction = dot == std::string::npos ? "" : text.substr(dot + 1);
  if (integer.empty()) return false;
  for (char c : integer) if (c < '0' || c > '9') return false;
  if (dot != std::string::npos && fraction.empty()) return false;
  for (char c : fraction) if (c < '0' || c > '9') return false;
  try {
    const double value = std::stod(text);
    return std::fabs(value - 1.0) < 1e-9 || std::fabs(value - 1.1) < 1e-9;
  } catch (...) {
    return false;
  }
}

TransportPorts parse_transport(const std::string& value) {
  const auto parts = split(value, ';');
  if (parts.empty() || (parts[0] != "RTP/AVP/UDP" && parts[0] != "RTP/AVP/TCP")) {
    fail("SETUP 应答的 Transport 前缀不符");
  }
  std::map<std::string, int> values;
  for (size_t i = 1; i < parts.size(); ++i) {
    if (parts[i] == "unicast") continue;
    const size_t eq = parts[i].find('=');
    if (eq == std::string::npos) fail("Transport 字段缺等号");
    const std::string name = parts[i].substr(0, eq);
    if (name != "server_port" && name != "remotectl_port" && name != "rtcp_port" && name != "client_port") {
      fail("Transport 含未知字段");
    }
    if (values.count(name) != 0) fail("Transport 字段重复");
    const std::string text = parts[i].substr(eq + 1);
    if (text == "-1" && (name == "rtcp_port" || name == "remotectl_port")) {
      values[name] = -1;
      continue;
    }
    const long long number = parse_decimal(text, 5);
    if (number < 0 || number > 65535) fail("Transport 端口不是有效整数");
    values[name] = static_cast<int>(number);
  }
  TransportPorts ports;
  ports.server_port = values.count("server_port") != 0 ? values["server_port"] : 0;
  if (ports.server_port < 1) fail("SETUP 应答缺有效视频端口");
  ports.remote_control_port = values.count("remotectl_port") != 0 ? values["remotectl_port"] : -1;
  if (ports.remote_control_port != -1 && (ports.remote_control_port < 1 || ports.remote_control_port > 65535)) {
    fail("回控端口必须是 -1 或有效端口");
  }
  return ports;
}

}  // namespace hisight
}  // namespace hicar
