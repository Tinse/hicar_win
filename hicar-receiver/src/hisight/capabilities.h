#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "hisight/rtsp.h"

namespace hicar {
namespace hisight {

struct HisightConfig {
  int screen_width = 1280;
  int screen_height = 720;
  int video_width = 1280;
  int video_height = 720;
  int fps = 30;
  int dpi = 160;
  std::optional<int> gop;
  std::optional<int> bitrate;
  bool touch_input = true;
  bool key_input = true;
  bool media_key_input = true;
  bool text_input = false;
  int device_type = 4;
};

struct VideoSelection {
  int width = 0;
  int height = 0;
  int fps = 0;
};

struct MediaSetup {
  VideoSelection selection;
  int video_port = 0;
  int remote_control_port = -1;
  std::vector<std::string> input_events;
  std::vector<std::string> input_vendors;
  std::optional<int> source_device_type;
};

struct TransportPorts {
  int server_port = 0;
  int remote_control_port = -1;
};

class Capabilities {
 public:
  explicit Capabilities(const HisightConfig& config);

  std::vector<std::string> advertised_events() const { return advertised_events_; }
  std::vector<std::string> advertised_vendors() const { return advertised_vendors_; }

  std::string response_body(const std::vector<uint8_t>& query) const;
  void select(const std::map<std::string, std::string>& fields);
  MediaSetup media_setup(int video_port, int remote_control_port) const;

  const std::optional<VideoSelection>& selection() const { return selection_; }
  const std::vector<std::string>& input_events() const { return input_events_; }
  const std::vector<std::string>& input_vendors() const { return input_vendors_; }

  static const std::vector<std::string>& touch_events();
  static const std::vector<std::string>& key_events();
  static const std::string& text_vendor();

 private:
  std::pair<std::vector<std::string>, std::vector<std::string>> input_selection(const std::string& text) const;
  bool accepted_version(const std::string& text) const;

  HisightConfig config_;
  std::vector<std::string> advertised_events_;
  std::set<std::string> optional_events_;
  std::set<std::string> required_events_;
  std::vector<std::string> advertised_vendors_;

  std::optional<VideoSelection> selection_;
  std::vector<std::string> input_events_;
  std::vector<std::string> input_vendors_;
  std::optional<int> source_device_type_;
};

TransportPorts parse_transport(const std::string& value);

}  // namespace hisight
}  // namespace hicar
