#pragma once

#include <capstone/capstone.h>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace scanner {

// 函数范围结构
struct FunctionRange {
    uint64_t start;
    uint64_t end;
};

// ELF段信息结构
struct SectionInfo {
    std::string name;
    uint64_t address;
    uint64_t size;
    std::vector<uint8_t> data;
};

// ELF符号信息结构
struct SymbolInfo {
    std::string name;
    uint64_t address;
    uint64_t size;
};

// ELF扫描器类 (x86-64架构)
class ElfScanner {
public:
    ElfScanner();
    ~ElfScanner();

    // 禁止拷贝
    ElfScanner(const ElfScanner&) = delete;
    ElfScanner& operator=(const ElfScanner&) = delete;

    // 加载ELF文件
    bool loadFile(const std::string& filePath);

    // 查找符号在GOT/PLT中的地址
    std::optional<uint64_t> findSymbolInGotPlt(const std::string& symbolName) const;

    // 获取.text段
    std::optional<SectionInfo> getTextSection() const;

    // 获取函数范围
    std::vector<FunctionRange> getFunctionRanges() const;

    // 查找包含指定地址的函数
    std::optional<FunctionRange> findFunctionContainingAddress(uint64_t address) const;

    // 获取段的RVA范围
    std::pair<std::optional<uint64_t>, std::optional<uint64_t>> 
        getSectionRangeRva(const std::string& sectionName) const;

    // 在指定范围内搜索字节序列
    std::optional<uint64_t> searchBytes(uint64_t start, uint64_t end, 
                                        const std::vector<uint8_t>& bytes) const;

    // 搜索所有匹配的字节序列
    std::vector<uint64_t> searchBytesAll(uint64_t start, uint64_t end, 
                                          const std::vector<uint8_t>& bytes) const;

    // 使用模式搜索数据 (支持通配符'?')
    std::optional<uint64_t> searchDataPattern(const std::string& pattern, 
                                               uint64_t start, uint64_t end) const;

    // 搜索所有匹配模式的数据
    std::vector<uint64_t> searchDataPatternAll(const std::string& pattern, 
                                                uint64_t start, uint64_t end) const;

    // 搜索可能的交叉引用 (相对偏移)
    std::optional<uint64_t> searchDataMaybeXref(uint64_t stringRva, 
                                                 uint64_t start, uint64_t end) const;

    // 搜索所有可能的交叉引用
    std::vector<uint64_t> searchDataMaybeXrefAll(uint64_t stringRva, 
                                                  uint64_t start, uint64_t end) const;

    // 使用模式搜索交叉引用
    std::optional<uint64_t> searchDataMaybeXrefPattern(const std::string& pattern,
                                                        uint64_t stringRva,
                                                        uint64_t start, uint64_t end) const;

    // 获取指定范围内所有call指令的目标地址
    std::vector<uint64_t> getAllCallRange(uint64_t start, uint64_t end) const;

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace scanner
