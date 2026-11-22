cmake_minimum_required(VERSION 3.20)
project(hicar_receiver LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (MSVC)
  add_compile_options(/W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

# 认证栈需要 OpenSSL 的 libcrypto（Ed25519 / X25519 / AES-GCM / 3072 位模幂）。
# 默认用本机 Anaconda 自带的 MSVC 版 libcrypto；换机器时改 HC_OPENSSL_ROOT 即可。
set(HC_OPENSSL_ROOT "D:/ProgramData/anaconda3/Library" CACHE PATH "OpenSSL (libcrypto) 根目录")
find_path(HC_OPENSSL_INCLUDE_DIR openssl/evp.h HINTS "${HC_OPENSSL_ROOT}/include" REQUIRED)
find_library(HC_LIBCRYPTO_LIBRARY NAMES libcrypto libcrypto-3-x64 HINTS "${HC_OPENSSL_ROOT}/lib" REQUIRED)

# Windows Mobile Hotspot 走 C++/WinRT（Windows SDK 自带投影头文件与 windowsapp.lib）。
find_path(HC_CPPWINRT_INCLUDE_DIR winrt/Windows.Foundation.h
  HINTS "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/cppwinrt" REQUIRED)

# 协议核心：纯字节处理，不依赖任何平台头文件，可单测。
add_library(hicar_core STATIC
  src/common/byte_buffer.cpp
  src/common/ea.cpp
  src/common/crc16_arc.cpp
  src/common/hex.cpp
  src/crypto/aes128.cpp
  src/crypto/sha256.cpp
  src/dmsdp/cipher.cpp
  src/dmsdp/audio_stream.cpp
  src/dmsdp/framing.cpp
  src/dmsdp/message.cpp
  src/dmsdp/session.cpp
  src/auth/authenticator.cpp
  src/auth/crypto.cpp
  src/auth/hichain.cpp
  src/auth/json.cpp
  src/auth/session.cpp
  src/auth/trust_store.cpp
  src/identity/default_identity.cpp
  src/identity/device_id.cpp
  src/nearby/car_info.cpp
  src/nearby/channel_management.cpp
  src/nearby/cipher.cpp
  src/nearby/data_channel.cpp
  src/nearby/frame.cpp
  src/nearby/session.cpp
  src/nearby/socket_messages.cpp
  src/nearby/tlv.cpp
  src/nearby/wifi_connection_info.cpp
)
target_include_directories(hicar_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src ${HC_OPENSSL_INCLUDE_DIR})
target_link_libraries(hicar_core PUBLIC ${HC_LIBCRYPTO_LIBRARY})

add_executable(hicar_receiver
  src/main.cpp
  src/app/bt_probe.cpp
  src/app/phone_sim.cpp
  src/app/receiver.cpp
  src/platform/bluetooth.cpp
  src/platform/tcp.cpp
  src/platform/hotspot.cpp
  src/platform/mf_decoder.cpp
  src/platform/frame_window.cpp
  src/platform/audio_player.cpp
  src/platform/app_window.cpp
  src/hisight/rtsp.cpp
  src/hisight/capabilities.cpp
  src/hisight/uibc.cpp
  src/hisight/video.cpp
  src/hisight/receiver.cpp
)
target_link_libraries(hicar_receiver PRIVATE hicar_core ws2_32 bthprops iphlpapi wlanapi windowsapp
  mfplat mf mfuuid wmcodecdspuuid ole32 user32 gdi32 winmm)
target_include_directories(hicar_receiver PRIVATE ${HC_CPPWINRT_INCLUDE_DIR})

add_executable(hicar_tests tests/test_core.cpp)
target_link_libraries(hicar_tests PRIVATE hicar_core)

add_executable(hicar_tests_crypto tests/test_crypto.cpp)
target_link_libraries(hicar_tests_crypto PRIVATE hicar_core)

add_executable(hicar_tests_nearby tests/test_nearby.cpp)
target_link_libraries(hicar_tests_nearby PRIVATE hicar_core)

add_executable(hicar_tests_session tests/test_session.cpp)
target_link_libraries(hicar_tests_session PRIVATE hicar_core)

add_executable(hicar_tests_wireless tests/test_wireless.cpp)
target_link_libraries(hicar_tests_wireless PRIVATE hicar_core)

add_executable(hicar_tests_auth tests/test_auth.cpp)
target_link_libraries(hicar_tests_auth PRIVATE hicar_core)

add_executable(hicar_tests_dmsdp tests/test_dmsdp.cpp)
target_link_libraries(hicar_tests_dmsdp PRIVATE hicar_core)

add_executable(hicar_tests_dmsdp_session tests/test_dmsdp_session.cpp)
target_link_libraries(hicar_tests_dmsdp_session PRIVATE hicar_core)

add_executable(hicar_tests_audio_stream tests/test_audio_stream.cpp)
target_link_libraries(hicar_tests_audio_stream PRIVATE hicar_core)

add_executable(hicar_hotspot_probe src/app/hotspot_probe.cpp src/platform/hotspot.cpp)
target_include_directories(hicar_hotspot_probe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${HC_CPPWINRT_INCLUDE_DIR})
target_link_libraries(hicar_hotspot_probe PRIVATE ws2_32 iphlpapi wlanapi windowsapp)

enable_testing()
add_test(NAME core COMMAND hicar_tests)
add_test(NAME crypto COMMAND hicar_tests_crypto)
add_test(NAME nearby COMMAND hicar_tests_nearby)
add_test(NAME session COMMAND hicar_tests_session)
add_test(NAME wireless COMMAND hicar_tests_wireless)
add_test(NAME auth COMMAND hicar_tests_auth)
add_test(NAME dmsdp COMMAND hicar_tests_dmsdp)
add_test(NAME dmsdp_session COMMAND hicar_tests_dmsdp_session)
add_test(NAME audio_stream COMMAND hicar_tests_audio_stream)

# 运行时需要 libcrypto DLL：拷到产物目录。
if (WIN32)
  get_filename_component(HC_OPENSSL_BIN_DIR "${HC_OPENSSL_ROOT}/bin" ABSOLUTE)
  file(GLOB HC_LIBCRYPTO_DLLS "${HC_OPENSSL_BIN_DIR}/libcrypto-3-x64.dll")
  if (HC_LIBCRYPTO_DLLS)
    add_custom_command(TARGET hicar_receiver POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different ${HC_LIBCRYPTO_DLLS} $<TARGET_FILE_DIR:hicar_receiver>)
    foreach (test_target hicar_tests_auth)
      add_custom_command(TARGET ${test_target} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${HC_LIBCRYPTO_DLLS} $<TARGET_FILE_DIR:${test_target}>)
    endforeach()
  endif()
endif()
