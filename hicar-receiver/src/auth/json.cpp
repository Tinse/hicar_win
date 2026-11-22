#include "auth/json.h"

#include <cstdio>
#include <cstdlib>
#include <limits>

namespace hicar::auth {

namespace {

const JsonValue* find_impl(const std::vector<std::pair<std::string, JsonValue>>& members,
                           std::string_view name, bool ignore_case) {
  for (const auto& member : members) {
    if (ignore_case) {
      if (member.first.size() != name.size()) continue;
      bool same = true;
      for (size_t i = 0; i < name.size(); ++i) {
        char a = member.first[i];
        char b = name[i];
        if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
        if (a != b) {
          same = false;
          break;
        }
      }
      if (same) return &member.second;
    } else if (member.first == name) {
      return &member.second;
    }
  }
  return nullptr;
}

class Parser {
 public:
  explicit Parser(std::string_view text) : text_(text) {}

  std::optional<JsonValue> parse() {
    skip_space();
    JsonValue value;
    if (!parse_value(&value)) return std::nullopt;
    skip_space();
    if (pos_ != text_.size()) return std::nullopt;
    return value;
  }

 private:
  void skip_space() {
    while (pos_ < text_.size()) {
      const char c = text_[pos_];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        ++pos_;
      } else {
        break;
      }
    }
  }

  bool parse_value(JsonValue* out) {
    if (pos_ >= text_.size()) return false;
    switch (text_[pos_]) {
      case '{': return parse_object(out);
      case '[': return parse_array(out);
      case '"': {
        out->type = JsonValue::Type::String;
        return parse_string(&out->text);
      }
      case 't':
        if (text_.substr(pos_, 4) == "true") {
          pos_ += 4;
          out->type = JsonValue::Type::Bool;
          out->boolean = true;
          return true;
        }
        return false;
      case 'f':
        if (text_.substr(pos_, 5) == "false") {
          pos_ += 5;
          out->type = JsonValue::Type::Bool;
          out->boolean = false;
          return true;
        }
        return false;
      case 'n':
        if (text_.substr(pos_, 4) == "null") {
          pos_ += 4;
          out->type = JsonValue::Type::Null;
          return true;
        }
        return false;
      default: return parse_number(out);
    }
  }

  bool parse_object(JsonValue* out) {
    out->type = JsonValue::Type::Object;
    ++pos_;  // '{'
    skip_space();
    if (pos_ < text_.size() && text_[pos_] == '}') {
      ++pos_;
      return true;
    }
    while (pos_ < text_.size()) {
      skip_space();
      if (pos_ >= text_.size() || text_[pos_] != '"') return false;
      std::string name;
      if (!parse_string(&name)) return false;
      skip_space();
      if (pos_ >= text_.size() || text_[pos_] != ':') return false;
      ++pos_;
      skip_space();
      JsonValue value;
      if (!parse_value(&value)) return false;
      out->object.emplace_back(std::move(name), std::move(value));
      skip_space();
      if (pos_ >= text_.size()) return false;
      if (text_[pos_] == ',') {
        ++pos_;
        continue;
      }
      if (text_[pos_] == '}') {
        ++pos_;
        return true;
      }
      return false;
    }
    return false;
  }

  bool parse_array(JsonValue* out) {
    out->type = JsonValue::Type::Array;
    ++pos_;  // '['
    skip_space();
    if (pos_ < text_.size() && text_[pos_] == ']') {
      ++pos_;
      return true;
    }
    while (pos_ < text_.size()) {
      skip_space();
      JsonValue value;
      if (!parse_value(&value)) return false;
      out->array.push_back(std::move(value));
      skip_space();
      if (pos_ >= text_.size()) return false;
      if (text_[pos_] == ',') {
        ++pos_;
        continue;
      }
      if (text_[pos_] == ']') {
        ++pos_;
        return true;
      }
      return false;
    }
    return false;
  }

  static void append_utf8(std::string* out, uint32_t code) {
    if (code < 0x80) {
      out->push_back(static_cast<char>(code));
    } else if (code < 0x800) {
      out->push_back(static_cast<char>(0xC0 | (code >> 6)));
      out->push_back(static_cast<char>(0x80 | (code & 0x3F)));
    } else if (code < 0x10000) {
      out->push_back(static_cast<char>(0xE0 | (code >> 12)));
      out->push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
      out->push_back(static_cast<char>(0x80 | (code & 0x3F)));
    } else {
      out->push_back(static_cast<char>(0xF0 | (code >> 18)));
      out->push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F)));
      out->push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
      out->push_back(static_cast<char>(0x80 | (code & 0x3F)));
    }
  }

  bool parse_hex4(uint32_t* value) {
    if (pos_ + 4 > text_.size()) return false;
    uint32_t result = 0;
    for (int i = 0; i < 4; ++i) {
      const char c = text_[pos_ + static_cast<size_t>(i)];
      result <<= 4;
      if (c >= '0' && c <= '9') {
        result |= static_cast<uint32_t>(c - '0');
      } else if (c >= 'a' && c <= 'f') {
        result |= static_cast<uint32_t>(c - 'a' + 10);
      } else if (c >= 'A' && c <= 'F') {
        result |= static_cast<uint32_t>(c - 'A' + 10);
      } else {
        return false;
      }
    }
    pos_ += 4;
    *value = result;
    return true;
  }

  bool parse_string(std::string* out) {
    if (pos_ >= text_.size() || text_[pos_] != '"') return false;
    ++pos_;
    out->clear();
    while (pos_ < text_.size()) {
      const char c = text_[pos_++];
      if (c == '"') return true;
      if (static_cast<unsigned char>(c) < 0x20) return false;
      if (c != '\\') {
        out->push_back(c);
        continue;
      }
      if (pos_ >= text_.size()) return false;
      const char escape = text_[pos_++];
      switch (escape) {
        case '"': out->push_back('"'); break;
        case '\\': out->push_back('\\'); break;
        case '/': out->push_back('/'); break;
        case 'b': out->push_back('\b'); break;
        case 'f': out->push_back('\f'); break;
        case 'n': out->push_back('\n'); break;
        case 'r': out->push_back('\r'); break;
        case 't': out->push_back('\t'); break;
        case 'u': {
          uint32_t code = 0;
          if (!parse_hex4(&code)) return false;
          if (code >= 0xD800 && code <= 0xDBFF) {
            if (pos_ + 2 <= text_.size() && text_[pos_] == '\\' && text_[pos_ + 1] == 'u') {
              pos_ += 2;
              uint32_t low = 0;
              if (!parse_hex4(&low)) return false;
              if (low >= 0xDC00 && low <= 0xDFFF) {
                code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
              }
            }
          }
          append_utf8(out, code);
          break;
        }
        default: return false;
      }
    }
    return false;
  }

  bool parse_number(JsonValue* out) {
    const size_t start = pos_;
    if (pos_ < text_.size() && (text_[pos_] == '-' || text_[pos_] == '+')) ++pos_;
    bool digits = false;
    while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
      ++pos_;
      digits = true;
    }
    if (pos_ < text_.size() && text_[pos_] == '.') {
      ++pos_;
      while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') ++pos_;
    }
    if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
      ++pos_;
      if (pos_ < text_.size() && (text_[pos_] == '-' || text_[pos_] == '+')) ++pos_;
      while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') ++pos_;
    }
    if (!digits) return false;
    out->type = JsonValue::Type::Number;
    out->text = std::string(text_.substr(start, pos_ - start));
    return true;
  }

  std::string_view text_;
  size_t pos_ = 0;
};

}  // namespace

const JsonValue* JsonValue::find(std::string_view name) const {
  if (type != Type::Object) return nullptr;
  return find_impl(object, name, false);
}

const JsonValue* JsonValue::find_ci(std::string_view name) const {
  if (type != Type::Object) return nullptr;
  return find_impl(object, name, true);
}

std::optional<std::string> JsonValue::as_string() const {
  if (type != Type::String) return std::nullopt;
  return text;
}

std::optional<int64_t> JsonValue::as_int() const {
  if (type != Type::Number || text.empty()) return std::nullopt;
  char* end = nullptr;
  errno = 0;
  const long long value = std::strtoll(text.c_str(), &end, 10);
  if (errno != 0 || end == nullptr || *end != '\0') return std::nullopt;
  return static_cast<int64_t>(value);
}

std::optional<bool> JsonValue::as_bool() const {
  if (type != Type::Bool) return std::nullopt;
  return boolean;
}

std::optional<JsonValue> parse_json(std::string_view text) { return Parser(text).parse(); }

std::string escape_json_string(std::string_view text) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(text.size());
  for (const char c : text) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          out += "\\u00";
          out.push_back(kHex[(static_cast<unsigned char>(c) >> 4) & 0xF]);
          out.push_back(kHex[static_cast<unsigned char>(c) & 0xF]);
        } else {
          out.push_back(c);
        }
    }
  }
  return out;
}

std::string write_json(const JsonValue& value) {
  switch (value.type) {
    case JsonValue::Type::Null: return "null";
    case JsonValue::Type::Bool: return value.boolean ? "true" : "false";
    case JsonValue::Type::Number: return value.text;
    case JsonValue::Type::String: return "\"" + escape_json_string(value.text) + "\"";
    case JsonValue::Type::Array: {
      std::string out = "[";
      for (size_t i = 0; i < value.array.size(); ++i) {
        if (i != 0) out.push_back(',');
        out += write_json(value.array[i]);
      }
      out.push_back(']');
      return out;
    }
    case JsonValue::Type::Object: {
      std::string out = "{";
      for (size_t i = 0; i < value.object.size(); ++i) {
        if (i != 0) out.push_back(',');
        out.push_back('"');
        out += escape_json_string(value.object[i].first);
        out += "\":";
        out += write_json(value.object[i].second);
      }
      out.push_back('}');
      return out;
    }
  }
  return "null";
}

}  // namespace hicar::auth
