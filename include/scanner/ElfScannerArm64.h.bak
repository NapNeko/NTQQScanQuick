#pragma once

#include <capstone/capstone.h>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace scanner {

// 函数范围结构 (复用)
struct FunctionRangeArm64 {
    uint64_t start;
    uint64_t end;
};

// ELF段信息结构 (复用)
struct SectionInfoArm64 {
    std::string name;
    uint64_t address;
    uint64_t size;
    std::vector<uint8_t> data;
};

// 指令信息结构
struct InstructionInfo {
    uint64_t address;
    uint32_t size;
    std::string mnemonic;
    std::string opStr;
    std::vector<uint8_t> bytes;
};

// ELF扫描器类 (ARM64架构)
class ElfScannerArm64 {
public:
    ElfScannerArm64();
    ~ElfScannerArm64();

    // 禁止拷贝
    ElfScannerArm64(const ElfScannerArm64&) = delete;
    ElfScannerArm64& operator=(const ElfScannerArm64&) = delete;

    // 加载ELF文件
    bool loadFile(const std::string& filePath);

    // 查找符号在GOT/PLT中的地址
    std::optional<uint64_t> findSymbolInGotPlt(const std::string& symbolName) const;

    // 获取.text段
    std::optional<SectionInfoArm64> getTextSection() const;

    // 获取函数范围
    std::vector<FunctionRangeArm64> getFunctionRanges() const;

    // 查找包含指定地址的函数
    std::optional<FunctionRangeArm64> findFunctionContainingAddress(uint64_t address) const;

    // 获取段的RVA范围
    std::pair<std::optional<uint64_t>, std::optional<uint64_t>> 
        getSectionRangeRva(const std::string& sectionName) const;

    // 在指定范围内搜索字节序列
    std::optional<uint64_t> searchBytes(uint64_t start, uint64_t end, 
                                        const std::vector<uint8_t>& bytes) const;

    // 搜索所有匹配的字节序列
    std::vector<uint64_t> searchBytesAll(uint64_t start, uint64_t end, 
                                          const std::vector<uint8_t>& bytes) const;

    // 使用模式搜索数据
    std::optional<uint64_t> searchDataPattern(const std::string& pattern, 
                                               uint64_t start, uint64_t end) const;

    // 搜索所有匹配模式的数据
    std::vector<uint64_t> searchDataPatternAll(const std::string& pattern, 
                                                uint64_t start, uint64_t end) const;

    // 搜索可能的交叉引用
    std::optional<uint64_t> searchDataMaybeXref(uint64_t stringRva, 
                                                 uint64_t start, uint64_t end) const;

    // 反汇编指定段
    std::tuple<std::vector<InstructionInfo>, uint64_t, uint64_t> 
        disassembleSection(const std::string& sectionName) const;

    // 根据RVA和数量反汇编
    std::tuple<std::vector<InstructionInfo>, uint64_t, uint64_t>
        disassembleSectionByRvaAndCount(uint64_t rva, size_t count) const;

    // 从反汇编中获取函数范围
    std::vector<FunctionRangeArm64> getFunctionRangesFromDisassembly(
        const std::vector<InstructionInfo>& insnList, 
        uint64_t startAddr, 
        uint64_t endAddr) const;

    // 通过反汇编搜索数据引用 (adrp + add模式)
    std::optional<uint64_t> searchDataByDisasm(
        const std::vector<InstructionInfo>& insnList, 
        uint64_t stringRva) const;

    // 使用模式搜索交叉引用
    std::optional<uint64_t> searchDataMaybeXrefPattern(const std::string& pattern,
                                                        uint64_t stringRva,
                                                        uint64_t start, uint64_t end) const;

    // 搜索所有可能的交叉引用
    std::vector<uint64_t> searchDataMaybeXrefAll(uint64_t stringRva, 
                                                  uint64_t start, uint64_t end) const;

    // 获取指定范围内所有bl指令的目标地址
    std::vector<uint64_t> getAllCallRange(uint64_t start, uint64_t end) const;

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace scanner
