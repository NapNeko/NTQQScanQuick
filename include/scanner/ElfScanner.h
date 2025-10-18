#pragma once

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

    // 通过解析 .eh_frame 节获取函数范围 (使用异常处理表)
    std::vector<FunctionRange> getFunctionRanges() const;

    // 查找包含指定地址的函数
    std::optional<FunctionRange> findFunctionContainingAddress(std::vector<scanner::FunctionRange> functions, uint64_t address) const;

    // 获取段的虚拟地址范围
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

    // 搜索可能的交叉引用 (RIP相对偏移)
    std::optional<uint64_t> searchDataMaybeXref(uint64_t targetAddr, 
                                                 uint64_t start, uint64_t end) const;

    // 搜索所有可能的交叉引用
    std::vector<uint64_t> searchDataMaybeXrefAll(uint64_t targetAddr, 
                                                  uint64_t start, uint64_t end) const;

    // 搜索 CALL 指令的交叉引用 (E8 opcode + RIP相对偏移)
    std::optional<uint64_t> searchCallMaybeXref(uint64_t targetAddr, 
                                                 uint64_t start, uint64_t end) const;

    // 搜索所有 CALL 指令的交叉引用
    std::vector<uint64_t> searchCallMaybeXrefAll(uint64_t targetAddr, 
                                                  uint64_t start, uint64_t end) const;

    // 获取数据
    std::vector<uint8_t> getData(uint64_t addr, size_t size) const;

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace scanner
