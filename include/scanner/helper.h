#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace scanner::helper
{
    // 将字节转为 "AA BB" 模式
    std::string bytesToPattern(const std::vector<uint8_t>& bytes);

    // 将 32 位小端转换为模式 "78 56 34 12"
    std::string le32ToPattern(uint32_t value);

    // ASCII 到模式 (可选 0 结尾)
    std::string asciiToPattern(const std::string& ascii, bool zeroTerminated = true);

    // u8 字面量到模式 (可选 0 结尾)
    // 提供 const char* 版本以兼容非 C++20 编译器（u8"..." 退化为 const char*）
    std::string u8ToPattern(const char* s, bool zeroTerminated = true);

    // 在支持 char8_t 的编译器上，提供 const char8_t* 重载
    #if defined(__cpp_char8_t) || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L) || (defined(__cplusplus) && __cplusplus >= 202002L)
    std::string u8ToPattern(const char8_t* s, bool zeroTerminated = true);
    #endif
}
