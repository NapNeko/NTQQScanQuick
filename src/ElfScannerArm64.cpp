#include "scanner/ElfScannerArm64.h"
#include <fstream>
#include <cstring>
#include <algorithm>

namespace scanner {

struct ElfScannerArm64::Impl {
    std::vector<uint8_t> fileData;
    std::vector<SectionInfoArm64> sections;
    csh csHandle = 0;
    bool initialized = false;

    ~Impl() {
        if (csHandle != 0) {
            cs_close(&csHandle);
        }
    }

    bool initCapstone() {
        if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &csHandle) != CS_ERR_OK) {
            return false;
        }
        cs_option(csHandle, CS_OPT_SKIPDATA, CS_OPT_ON);
        return true;
    }

    bool parseElf() {
        // 简化的ELF解析
        return true;
    }
};

ElfScannerArm64::ElfScannerArm64() : pImpl(std::make_unique<Impl>()) {}

ElfScannerArm64::~ElfScannerArm64() = default;

bool ElfScannerArm64::loadFile(const std::string& filePath) {
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

std::optional<uint64_t> ElfScannerArm64::findSymbolInGotPlt(const std::string& symbolName) const {
    return std::nullopt;
}

std::optional<SectionInfoArm64> ElfScannerArm64::getTextSection() const {
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

std::vector<FunctionRangeArm64> ElfScannerArm64::getFunctionRanges() const {
    std::vector<FunctionRangeArm64> functions;
    
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
        FunctionRangeArm64* currentFunc = nullptr;

        for (size_t i = 0; i < count; i++) {
            // ARM64函数序言: stp x29, x30, [sp, #-xx]!
            if (strcmp(insn[i].mnemonic, "stp") == 0 &&
                strstr(insn[i].op_str, "x29") != nullptr &&
                strstr(insn[i].op_str, "x30") != nullptr) {
                
                if (currentFunc != nullptr) {
                    functions.push_back(*currentFunc);
                }
                currentFunc = new FunctionRangeArm64{insn[i].address, 0};
            }
            // 函数返回: ret
            else if (strcmp(insn[i].mnemonic, "ret") == 0) {
                if (currentFunc != nullptr) {
                    currentFunc->end = insn[i].address + insn[i].size;
                    functions.push_back(*currentFunc);
                    delete currentFunc;
                    currentFunc = nullptr;
                }
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

std::optional<FunctionRangeArm64> ElfScannerArm64::findFunctionContainingAddress(uint64_t address) const {
    auto functions = getFunctionRanges();
    
    for (const auto& func : functions) {
        if (func.start <= address && address < func.end) {
            return func;
        }
    }
    return std::nullopt;
}

std::pair<std::optional<uint64_t>, std::optional<uint64_t>> 
ElfScannerArm64::getSectionRangeRva(const std::string& sectionName) const {
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

std::optional<uint64_t> ElfScannerArm64::searchBytes(uint64_t start, uint64_t end,
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

std::vector<uint64_t> ElfScannerArm64::searchBytesAll(uint64_t start, uint64_t end,
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

std::optional<uint64_t> ElfScannerArm64::searchDataPattern(const std::string& pattern,
                                                            uint64_t start, uint64_t end) const {
    return std::nullopt;
}

std::vector<uint64_t> ElfScannerArm64::searchDataPatternAll(const std::string& pattern,
                                                             uint64_t start, uint64_t end) const {
    return std::vector<uint64_t>();
}

std::optional<uint64_t> ElfScannerArm64::searchDataMaybeXref(uint64_t stringRva,
                                                              uint64_t start, uint64_t end) const {
    return std::nullopt;
}

std::tuple<std::vector<InstructionInfo>, uint64_t, uint64_t>
ElfScannerArm64::disassembleSection(const std::string& sectionName) const {
    std::vector<InstructionInfo> insnList;
    
    if (!pImpl->initialized) {
        return {insnList, 0, 0};
    }

    for (const auto& section : pImpl->sections) {
        if (section.name == sectionName) {
            cs_insn* insn = nullptr;
            size_t count = cs_disasm(pImpl->csHandle,
                                     section.data.data(),
                                     section.data.size(),
                                     section.address,
                                     0,
                                     &insn);

            if (count > 0) {
                for (size_t i = 0; i < count; i++) {
                    InstructionInfo info;
                    info.address = insn[i].address;
                    info.size = insn[i].size;
                    info.mnemonic = insn[i].mnemonic;
                    info.opStr = insn[i].op_str;
                    info.bytes.assign(insn[i].bytes, insn[i].bytes + insn[i].size);
                    insnList.push_back(info);
                }
                cs_free(insn, count);
            }

            return {insnList, section.address, section.address + section.size};
        }
    }

    return {insnList, 0, 0};
}

std::tuple<std::vector<InstructionInfo>, uint64_t, uint64_t>
ElfScannerArm64::disassembleSectionByRvaAndCount(uint64_t rva, size_t count) const {
    std::vector<InstructionInfo> insnList;
    return {insnList, 0, 0};
}

std::vector<FunctionRangeArm64> ElfScannerArm64::getFunctionRangesFromDisassembly(
    const std::vector<InstructionInfo>& insnList,
    uint64_t startAddr,
    uint64_t endAddr) const {
    
    std::vector<FunctionRangeArm64> functions;
    FunctionRangeArm64* currentFunc = nullptr;

    for (size_t i = 0; i < insnList.size(); i++) {
        const auto& insn = insnList[i];

        // 检测函数开始
        if ((insn.mnemonic == "stp" && 
             insn.opStr.find("x29") != std::string::npos &&
             insn.opStr.find("x30") != std::string::npos) ||
            (insn.mnemonic == "sub" && insn.opStr.find("sp") != std::string::npos)) {
            
            if (currentFunc != nullptr) {
                currentFunc->end = insn.address;
                functions.push_back(*currentFunc);
            }
            currentFunc = new FunctionRangeArm64{insn.address, 0};
        }
        // 检测函数结束
        else if (insn.mnemonic == "ret" || insn.mnemonic == "b") {
            if (currentFunc != nullptr) {
                currentFunc->end = insn.address + insn.size;
                functions.push_back(*currentFunc);
                delete currentFunc;
                currentFunc = nullptr;
            }
        }
    }

    if (currentFunc != nullptr) {
        currentFunc->end = endAddr;
        functions.push_back(*currentFunc);
        delete currentFunc;
    }

    return functions;
}

std::optional<uint64_t> ElfScannerArm64::searchDataByDisasm(
    const std::vector<InstructionInfo>& insnList,
    uint64_t stringRva) const {
    
    // 查找 adrp + add 模式
    for (size_t i = 0; i < insnList.size() - 1; i++) {
        if (insnList[i].mnemonic == "adrp" && insnList[i + 1].mnemonic == "add") {
            // 这里需要详细的ARM64指令解析
            // 简化实现
        }
    }
    return std::nullopt;
}

std::optional<uint64_t> ElfScannerArm64::searchDataMaybeXrefPattern(
    const std::string& pattern, uint64_t stringRva, uint64_t start, uint64_t end) const {
    return std::nullopt;
}

std::vector<uint64_t> ElfScannerArm64::searchDataMaybeXrefAll(
    uint64_t stringRva, uint64_t start, uint64_t end) const {
    return std::vector<uint64_t>();
}

std::vector<uint64_t> ElfScannerArm64::getAllCallRange(uint64_t start, uint64_t end) const {
    std::vector<uint64_t> callList;
    
    if (!pImpl->initialized) {
        return callList;
    }

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
                    if (strcmp(insn[i].mnemonic, "bl") == 0) {
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
