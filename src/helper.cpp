#include "scanner/helper.h"
#include <sstream>
#include <iomanip>

namespace scanner::helper
{
    std::string bytesToPattern(const std::vector<uint8_t>& bytes)
    {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            if (i) oss << ' ';
            oss << std::setw(2) << static_cast<int>(bytes[i]);
        }
        return oss.str();
    }

    std::string le32ToPattern(uint32_t value)
    {
        std::vector<uint8_t> b = {
            static_cast<uint8_t>(value & 0xFF),
            static_cast<uint8_t>((value >> 8) & 0xFF),
            static_cast<uint8_t>((value >> 16) & 0xFF),
            static_cast<uint8_t>((value >> 24) & 0xFF)
        };
        return bytesToPattern(b);
    }

    std::string asciiToPattern(const std::string& ascii, bool zeroTerminated)
    {
        std::vector<uint8_t> b(ascii.begin(), ascii.end());
        if (zeroTerminated) b.push_back(0x00);
        return bytesToPattern(b);
    }

    std::string u8ToPattern(const char* s, bool zeroTerminated)
    {
        // Treat input as UTF-8 bytes
        std::vector<uint8_t> b;
        if (s)
        {
            const unsigned char* p = reinterpret_cast<const unsigned char*>(s);
            while (*p)
            {
                b.push_back(*p);
                ++p;
            }
        }
        if (zeroTerminated) b.push_back(0x00);
        return bytesToPattern(b);
    }

    #if defined(__cpp_char8_t) || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L) || (defined(__cplusplus) && __cplusplus >= 202002L)
    std::string u8ToPattern(const char8_t* s, bool zeroTerminated)
    {
        // Convert char8_t* to byte sequence until \0
        std::vector<uint8_t> b;
        if (s)
        {
            const char8_t* p = s;
            while (*p)
            {
                b.push_back(static_cast<uint8_t>(*p));
                ++p;
            }
        }
        if (zeroTerminated) b.push_back(0x00);
        return bytesToPattern(b);
    }
    #endif
}
