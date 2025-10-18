#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace scanner
{

    // 函数范围结构
    struct PeFunctionRange
    {
        uint64_t start;
        uint64_t end;
    };

    // PE扫描器类 (Windows PE文件, x86-64架构)
    class PeScanner
    {
    public:
        PeScanner();
        ~PeScanner();

        // 禁止拷贝
        PeScanner(const PeScanner &) = delete;
        PeScanner &operator=(const PeScanner &) = delete;

        // 加载PE文件
        bool loadFile(const std::string &filePath);

        // 获取函数范围
        std::vector<PeFunctionRange> getFunctionRanges() const;

        // 通过解析 .pdata 节获取函数范围 (使用异常处理表)
        std::vector<PeFunctionRange> getFunctionRangesByUnWind() const;

        std::optional<PeFunctionRange> findFunctionContainingAddress(std::vector<scanner::PeFunctionRange> functions, uint64_t address) const;

        // 获取段的RVA范围
        std::pair<std::optional<uint64_t>, std::optional<uint64_t>>
        getSectionRangeRva(const std::string &sectionName) const;

        // 获取段的实际地址范围 (ImageBase + RVA)
        std::pair<std::optional<uint64_t>, std::optional<uint64_t>>
        getSectionRangeReal(const std::string &sectionName) const;

        // 在指定范围内搜索字节序列
        std::optional<uint64_t> searchBytes(uint64_t start, uint64_t end,
                                            const std::vector<uint8_t> &bytes) const;

        // 搜索所有匹配的字节序列
        std::vector<uint64_t> searchBytesAll(uint64_t start, uint64_t end,
                                             const std::vector<uint8_t> &bytes) const;

        // 搜索可能的交叉引用 (相对偏移)
        std::optional<uint64_t> searchDataMaybeXref(uint64_t stringRva,
                                                    uint64_t start, uint64_t end) const;

        // 搜索所有可能的交叉引用
        std::vector<uint64_t> searchDataMaybeXrefAll(uint64_t stringRva,
                                                     uint64_t start, uint64_t end) const;

        // 搜索call指令的交叉引用
        std::optional<uint64_t> searchCallMaybeXref(uint64_t stringRva,
                                                    uint64_t start, uint64_t end) const;

        // 使用模式搜索数据 (支持通配符'?')
        std::optional<uint64_t> searchDataPattern(const std::string &pattern,
                                                  uint64_t start, uint64_t end) const;

        // 搜索所有匹配模式的数据
        std::vector<uint64_t> searchDataPatternAll(const std::string &pattern,
                                                   uint64_t start, uint64_t end) const;

        // 扫描类型信息
        std::vector<uint64_t> typeinfoScanAll(uint64_t stringRva,
                                              uint64_t start, uint64_t end) const;

        // 获取指定范围内所有call指令的目标地址
        std::vector<uint64_t> getAllCallRange(uint64_t start, uint64_t end) const;

        // 获取数据
        std::vector<uint8_t> getData(uint64_t rva, size_t size) const;

        // 获取ImageBase
        uint64_t getImageBase() const;

    private:
        struct Impl;
        std::unique_ptr<Impl> pImpl;
    };

} // namespace scanner
