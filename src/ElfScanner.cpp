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
    std::vector<FunctionRange> functions;
    
    if (!pImpl->initialized) {
        return functions;
    }

    auto textSection = getTextSection();
    if (!textSection) {
        return functions;
    }

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(pImpl->csHandle, 
                             textSection->data.data(), 
                             textSection->data.size(),
                             textSection->address, 
                             0, 
                             &insn);

    if (count > 0) {
        FunctionRange* currentFunc = nullptr;
        
        for (size_t i = 0; i < count; i++) {
            // 检测函数序言: push rbp
            if (strcmp(insn[i].mnemonic, "push") == 0 && 
                strcmp(insn[i].op_str, "rbp") == 0) {
                
                if (currentFunc != nullptr) {
                    functions.push_back(*currentFunc);
                }
                currentFunc = new FunctionRange{insn[i].address, 0};
            }
            // 检测: mov rbp, rsp
            else if (strcmp(insn[i].mnemonic, "mov") == 0 && 
                     strcmp(insn[i].op_str, "rbp, rsp") == 0) {
                
                if (currentFunc != nullptr) {
                    functions.push_back(*currentFunc);
                }
                currentFunc = new FunctionRange{insn[i].address, 0};
            }

            if (currentFunc != nullptr) {
                currentFunc->end = insn[i].address + insn[i].size;
            }
        }

        if (currentFunc != nullptr) {
            functions.push_back(*currentFunc);
            delete currentFunc;
        }

        cs_free(insn, count);
    }

    return functions;
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
