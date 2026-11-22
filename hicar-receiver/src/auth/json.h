#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace hicar::auth {

// 最小 JSON 值：保留对象成员的原始顺序（认证库消息的字段顺序不能变）。
struct JsonValue {
  enum class Type { Null, Bool, Number, String, Array, Object };

  Type type = Type::Null;
  bool boolean = false;
  std::string text;  // Number 为原始文本，String 为解码后的内容
  std::vector<JsonValue> array;
  std::vector<std::pair<std::string, JsonValue>> object;

  bool is_object() const { return type == Type::Object; }
  bool is_string() const { return type == Type::String; }
  bool is_number() const { return type == Type::Number; }
  bool is_bool() const { return type == Type::Bool; }

  const JsonValue* find(std::string_view name) const;     // 区分大小写
  const JsonValue* find_ci(std::string_view name) const;  // 不区分大小写，返回第一个匹配

  std::optional<std::string> as_string() const;
  std::optional<int64_t> as_int() const;
  std::optional<bool> as_bool() const;
};

std::optional<JsonValue> parse_json(std::string_view text);

// 紧凑序列化：无空白，保留成员顺序；非 ASCII 字符原样输出。
std::string write_json(const JsonValue& value);

// 把字符串转义成 JSON 字符串内容（不含两侧引号）。
std::string escape_json_string(std::string_view text);

}  // namespace hicar::auth
