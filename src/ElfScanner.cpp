#include "scanner/ElfScanner.h"
#include <fstream>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace scanner {

// PIMPL实现
struct ElfScanner::Impl {
    std::vector<uint8_t> fileData;
    std::vector<SectionInfo> sections;
    std::vector<SymbolInfo> symbols;
    csh csHandle = 0;
    bool initialized = false;
    std::vector<FunctionRange> functionRanges; // 缓存函数范围

    ~Impl() {
        if (csHandle != 0) {
            cs_close(&csHandle);
        }
    }

    bool initCapstone() {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &csHandle) != CS_ERR_OK) {
            return false;
        }
        cs_option(csHandle, CS_OPT_SKIPDATA, CS_OPT_ON);
        return true;
    }

    // 简化的ELF解析 - 仅用于演示
    bool parseElf() {
        // 这里需要完整的ELF解析实现
        // 为简化起见，这里仅做基本结构
        return true;
    }

    // 读取ULEB128编码的值
    uint64_t readULEB128(const uint8_t*& ptr, const uint8_t* end) {
        uint64_t result = 0;
        int shift = 0;
        while (ptr < end) {
            uint8_t byte = *ptr++;
            result |= static_cast<uint64_t>(byte & 0x7F) << shift;
            if ((byte & 0x80) == 0) {
                break;
            }
            shift += 7;
        }
        return result;
    }

    // 读取SLEB128编码的值
    int64_t readSLEB128(const uint8_t*& ptr, const uint8_t* end) {
        int64_t result = 0;
        int shift = 0;
        uint8_t byte;
        while (ptr < end) {
            byte = *ptr++;
            result |= static_cast<int64_t>(byte & 0x7F) << shift;
            shift += 7;
            if ((byte & 0x80) == 0) {
                break;
            }
        }
        // 符号扩展
        if (shift < 64 && (byte & 0x40)) {
            result |= -(1LL << shift);
        }
        return result;
    }

    // 读取编码的指针值
    uint64_t readEncodedPointer(const uint8_t*& ptr, const uint8_t* end, 
                                 uint8_t encoding, uint64_t baseAddr) {
        if (encoding == 0xFF) { // DW_EH_PE_omit
            return 0;
        }

        uint64_t result = 0;
        const uint8_t* startPtr = ptr;

        // 读取值
        switch (encoding & 0x0F) {
            case 0x00: // DW_EH_PE_absptr
                if (ptr + 8 <= end) {
                    std::memcpy(&result, ptr, 8);
                    ptr += 8;
                }
                break;
            case 0x01: // DW_EH_PE_uleb128
                result = readULEB128(ptr, end);
                break;
            case 0x02: // DW_EH_PE_udata2
                if (ptr + 2 <= end) {
                    std::memcpy(&result, ptr, 2);
                    ptr += 2;
                }
                break;
            case 0x03: // DW_EH_PE_udata4
                if (ptr + 4 <= end) {
                    std::memcpy(&result, ptr, 4);
                    ptr += 4;
                }
                break;
            case 0x04: // DW_EH_PE_udata8
                if (ptr + 8 <= end) {
                    std::memcpy(&result, ptr, 8);
                    ptr += 8;
                }
                break;
            case 0x09: // DW_EH_PE_sleb128
                result = static_cast<uint64_t>(readSLEB128(ptr, end));
                break;
            case 0x0A: // DW_EH_PE_sdata2
                if (ptr + 2 <= end) {
                    int16_t val;
                    std::memcpy(&val, ptr, 2);
                    result = static_cast<uint64_t>(val);
                    ptr += 2;
                }
                break;
            case 0x0B: // DW_EH_PE_sdata4
                if (ptr + 4 <= end) {
                    int32_t val;
                    std::memcpy(&val, ptr, 4);
                    result = static_cast<uint64_t>(val);
                    ptr += 4;
                }
                break;
            case 0x0C: // DW_EH_PE_sdata8
                if (ptr + 8 <= end) {
                    int64_t val;
                    std::memcpy(&val, ptr, 8);
                    result = static_cast<uint64_t>(val);
                    ptr += 8;
                }
                break;
            default:
                return 0;
        }

        // 应用相对地址修正
        switch (encoding & 0x70) {
            case 0x00: // DW_EH_PE_absptr
                break;
            case 0x10: // DW_EH_PE_pcrel
                result += baseAddr + (startPtr - fileData.data());
                break;
            case 0x20: // DW_EH_PE_textrel
            case 0x30: // DW_EH_PE_datarel
            case 0x40: // DW_EH_PE_funcrel
            case 0x50: // DW_EH_PE_aligned
                // 暂不支持这些编码方式
                break;
        }

        return result;
    }

    // 解析 .eh_frame 段以提取函数范围
    void parseEhFrame() {
        functionRanges.clear();

        // 查找 .eh_frame 段
        const SectionInfo* ehFrameSection = nullptr;
        for (const auto& section : sections) {
            if (section.name == ".eh_frame") {
                ehFrameSection = &section;
                break;
            }
        }

        if (!ehFrameSection || ehFrameSection->data.empty()) {
            return;
        }

        const uint8_t* ptr = ehFrameSection->data.data();
        const uint8_t* end = ptr + ehFrameSection->data.size();
        uint64_t baseAddr = ehFrameSection->address;

        while (ptr < end) {
            const uint8_t* entryStart = ptr;
            
            // 读取长度字段
            if (ptr + 4 > end) break;
            uint32_t length;
            std::memcpy(&length, ptr, 4);
            ptr += 4;

            if (length == 0) break; // 终止符

            // 检查是否为扩展长度
            bool is64bit = false;
            if (length == 0xFFFFFFFF) {
                if (ptr + 8 > end) break;
                uint64_t length64;
                std::memcpy(&length64, ptr, 8);
                ptr += 8;
                length = static_cast<uint32_t>(length64);
                is64bit = true;
            }

            const uint8_t* entryEnd = ptr + length;
            if (entryEnd > end) break;

            // 读取 CIE ID
            uint32_t cieId;
            std::memcpy(&cieId, ptr, 4);
            ptr += 4;

            if (cieId == 0) {
                // 这是一个 CIE (Common Information Entry),跳过
                ptr = entryEnd;
                continue;
            }

            // 这是一个 FDE (Frame Description Entry)
            // CIE ID 实际上是指向对应 CIE 的偏移量

            // 我们需要找到对应的 CIE 来获取编码格式
            // 为了简化,我们假设使用常见的编码格式
            uint8_t fdeEncoding = 0x1B; // DW_EH_PE_pcrel | DW_EH_PE_sdata4

            // 读取 PC begin (函数起始地址)
            uint64_t pcBegin = readEncodedPointer(ptr, entryEnd, fdeEncoding, 
                                                   baseAddr + (entryStart - ehFrameSection->data.data()));

            // 读取 PC range (函数大小)
            uint64_t pcRange = readEncodedPointer(ptr, entryEnd, fdeEncoding & 0x0F, 0);

            if (pcBegin > 0 && pcRange > 0) {
                FunctionRange range;
                range.start = pcBegin;
                range.end = pcBegin + pcRange;
                functionRanges.push_back(range);
            }

            ptr = entryEnd;
        }

        // 按起始地址排序
        std::sort(functionRanges.begin(), functionRanges.end(), 
                  [](const FunctionRange& a, const FunctionRange& b) {
                      return a.start < b.start;
                  });
    }
};

ElfScanner::ElfScanner() : pImpl(std::make_unique<Impl>()) {}

ElfScanner::~ElfScanner() = default;

bool ElfScanner::loadFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return false;
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    pImpl->fileData.resize(fileSize);
    file.read(reinterpret_cast<char*>(pImpl->fileData.data()), fileSize);

    if (!pImpl->initCapstone()) {
        return false;
    }

    pImpl->initialized = pImpl->parseElf();
    
    // 解析 .eh_frame 段以获取函数范围
    if (pImpl->initialized) {
        pImpl->parseEhFrame();
    }
    
    return pImpl->initialized;
}

std::optional<uint64_t> ElfScanner::findSymbolInGotPlt(const std::string& symbolName) const {
    if (!pImpl->initialized) {
        return std::nullopt;
    }

    for (const auto& sym : pImpl->symbols) {
        if (sym.name == symbolName) {
            return sym.address;
        }
    }
    return std::nullopt;
}

std::optional<SectionInfo> ElfScanner::getTextSection() const {
    if (!pImpl->initialized) {
        return std::nullopt;
    }

    for (const auto& section : pImpl->sections) {
        if (section.name == ".text") {
            return section;
        }
    }
    return std::nullopt;
}

std::vector<FunctionRange> ElfScanner::getFunctionRanges() const {
    if (!pImpl->initialized) {
        return std::vector<FunctionRange>();
    }

    // 直接返回从 .eh_frame 解析得到的函数范围
    return pImpl->functionRanges;
}

std::optional<FunctionRange> ElfScanner::findFunctionContainingAddress(uint64_t address) const {
    auto functions = getFunctionRanges();
    
    for (const auto& func : functions) {
        if (func.start <= address && address < func.end) {
            return func;
        }
    }
    return std::nullopt;
}

std::pair<std::optional<uint64_t>, std::optional<uint64_t>> 
ElfScanner::getSectionRangeRva(const std::string& sectionName) const {
    if (!pImpl->initialized) {
        return {std::nullopt, std::nullopt};
    }

    for (const auto& section : pImpl->sections) {
        if (section.name == sectionName) {
            return {section.address, section.address + section.size};
        }
    }
    return {std::nullopt, std::nullopt};
}

std::optional<uint64_t> ElfScanner::searchBytes(uint64_t start, uint64_t end, 
                                                 const std::vector<uint8_t>& bytes) const {
    if (!pImpl->initialized || bytes.empty()) {
        return std::nullopt;
    }

    for (const auto& section : pImpl->sections) {
        if (section.address <= start && start < section.address + section.size) {
            size_t offset = start - section.address;
            size_t searchLen = std::min(end - start + 1, section.size - offset);

            for (size_t i = offset; i <= offset + searchLen - bytes.size(); i++) {
                if (std::memcmp(&section.data[i], bytes.data(), bytes.size()) == 0) {
                    return section.address + i;
                }
            }
        }
    }
    return std::nullopt;
}

std::vector<uint64_t> ElfScanner::searchBytesAll(uint64_t start, uint64_t end, 
                                                  const std::vector<uint8_t>& bytes) const {
    std::vector<uint64_t> results;
    
    if (!pImpl->initialized || bytes.empty()) {
        return results;
    }

    for (const auto& section : pImpl->sections) {
        if (section.address <= start && start < section.address + section.size) {
            size_t offset = start - section.address;
            size_t searchLen = std::min(end - start + 1, section.size - offset);

            for (size_t i = offset; i <= offset + searchLen - bytes.size(); i++) {
                if (std::memcmp(&section.data[i], bytes.data(), bytes.size()) == 0) {
                    results.push_back(section.address + i);
                }
            }
        }
    }
    return results;
}

// 辅助函数: 将十六进制字符串转换为字节
static std::vector<uint8_t> hexStringToBytes(const std::string& hexStr) {
    std::vector<uint8_t> bytes;
    std::string cleanHex = hexStr;
    
    // 移除空格和"0x"前缀
    cleanHex.erase(std::remove(cleanHex.begin(), cleanHex.end(), ' '), cleanHex.end());
    size_t pos = 0;
    while ((pos = cleanHex.find("0x", pos)) != std::string::npos) {
        cleanHex.erase(pos, 2);
    }

    for (size_t i = 0; i < cleanHex.length(); i += 2) {
        std::string byteStr = cleanHex.substr(i, 2);
        bytes.push_back(static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16)));
    }
    return bytes;
}

std::optional<uint64_t> ElfScanner::searchDataPattern(const std::string& pattern, 
                                                       uint64_t start, uint64_t end) const {
    if (!pImpl->initialized) {
        return std::nullopt;
    }

    std::string cleanPattern = pattern;
    cleanPattern.erase(std::remove(cleanPattern.begin(), cleanPattern.end(), ' '), cleanPattern.end());
    std::transform(cleanPattern.begin(), cleanPattern.end(), cleanPattern.begin(), ::tolower);

    for (const auto& section : pImpl->sections) {
        if (section.address <= start && start < section.address + section.size) {
            size_t offset = start - section.address;
            size_t searchLen = std::min(end - start + 1, section.size - offset);
            size_t patternLen = cleanPattern.length() / 2;

            for (size_t i = offset; i <= offset + searchLen - patternLen; i++) {
                bool match = true;
                for (size_t j = 0; j < cleanPattern.length(); j++) {
                    if (cleanPattern[j] == '?') {
                        continue;
                    }
                    
                    char hexChar = cleanPattern[j];
                    uint8_t byte = section.data[i + j / 2];
                    char byteHex = (j % 2 == 0) ? 
                        ((byte >> 4) & 0xF) : (byte & 0xF);
                    byteHex += (byteHex < 10) ? '0' : ('a' - 10);

                    if (hexChar != byteHex) {
                        match = false;
                        break;
                    }
                }
                
                if (match) {
                    return section.address + i;
                }
            }
        }
    }
    return std::nullopt;
}

std::vector<uint64_t> ElfScanner::searchDataPatternAll(const std::string& pattern, 
                                                        uint64_t start, uint64_t end) const {
    std::vector<uint64_t> results;
    // 类似searchDataPattern的实现，但收集所有匹配
    return results;
}

std::optional<uint64_t> ElfScanner::searchDataMaybeXref(uint64_t stringRva, 
                                                         uint64_t start, uint64_t end) const {
    if (!pImpl->initialized) {
        return std::nullopt;
    }

    for (const auto& section : pImpl->sections) {
        if (section.address <= start && start < section.address + section.size) {
            size_t offset = start - section.address;
            size_t searchLen = std::min(end - start + 1, section.size - offset);

            for (size_t i = offset; i <= offset + searchLen - 4; i++) {
                int32_t relOffset;
                std::memcpy(&relOffset, &section.data[i], sizeof(int32_t));
                
                uint64_t refAddr = section.address + i + 4 + relOffset;
                if (refAddr == stringRva) {
                    return section.address + i;
                }
            }
        }
    }
    return std::nullopt;
}

std::vector<uint64_t> ElfScanner::searchDataMaybeXrefAll(uint64_t stringRva, 
                                                          uint64_t start, uint64_t end) const {
    std::vector<uint64_t> results;
    
    if (!pImpl->initialized) {
        return results;
    }

    for (const auto& section : pImpl->sections) {
        if (section.address <= start && start < section.address + section.size) {
            size_t offset = start - section.address;
            size_t searchLen = std::min(end - start + 1, section.size - offset);

            for (size_t i = offset; i <= offset + searchLen - 4; i++) {
                int32_t relOffset;
                std::memcpy(&relOffset, &section.data[i], sizeof(int32_t));
                
                uint64_t refAddr = section.address + i + 4 + relOffset;
                if (refAddr == stringRva) {
                    results.push_back(section.address + i);
                }
            }
        }
    }
    return results;
}

std::optional<uint64_t> ElfScanner::searchDataMaybeXrefPattern(
    const std::string& pattern, uint64_t stringRva, uint64_t start, uint64_t end) const {
    // 模式匹配后再检查交叉引用
    return std::nullopt;
}

std::vector<uint64_t> ElfScanner::getAllCallRange(uint64_t start, uint64_t end) const {
    std::vector<uint64_t> callList;
    
    if (!pImpl->initialized) {
        return callList;
    }

    // 找到包含该范围的段
    for (const auto& section : pImpl->sections) {
        if (section.address <= start && start < section.address + section.size) {
            size_t offset = start - section.address;
            size_t codeSize = end - start;

            cs_insn* insn = nullptr;
            size_t count = cs_disasm(pImpl->csHandle,
                                     &section.data[offset],
                                     codeSize,
                                     start,
                                     0,
                                     &insn);

            if (count > 0) {
                for (size_t i = 0; i < count; i++) {
                    if (strcmp(insn[i].mnemonic, "call") == 0) {
                        uint64_t target = strtoull(insn[i].op_str, nullptr, 16);
                        callList.push_back(target);
                    }
                }
                cs_free(insn, count);
            }
            break;
        }
    }

    return callList;
}

} // namespace scanner
