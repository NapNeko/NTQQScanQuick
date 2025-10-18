#include <iostream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <set>
#include "scanner/PeScanner.h"
#include "scanner/helper.h"

void getOffset(const std::string &pePath)
{
    std::cout << "\n=== Getting Offsets ===\n";
    std::cout << "Target file: " << pePath << "\n\n";

    scanner::PeScanner pe;

    // Load PE file
    if (!pe.loadFile(pePath))
    {
        std::cerr << "[ERROR] Failed to load PE file: " << pePath << "\n";
        return;
    }

    uint64_t pe_image_base = pe.getImageBase();
    std::cout << "[INFO] ImageBase: 0x" << std::hex << std::uppercase << pe_image_base << "\n";

    // 加载段区
    auto section_rdata_range = pe.getSectionRangeRva(".rdata");
    if (!section_rdata_range.first || !section_rdata_range.second)
    {
        std::cerr << "[ERROR] .rdata section not found\n";
        return;
    }
    uint64_t rdata_start = *section_rdata_range.first;
    uint64_t rdata_end = *section_rdata_range.second;
    std::cout << "[INFO] .rdata range: 0x" << std::hex << rdata_start
              << " - 0x" << rdata_end << "\n";

    auto section_text_range = pe.getSectionRangeRva(".text");
    if (!section_text_range.first || !section_text_range.second)
    {
        std::cerr << "[ERROR] .text section not found\n";
        return;
    }
    uint64_t text_start = *section_text_range.first;
    uint64_t text_end = *section_text_range.second;
    std::cout << "[INFO] .text range: 0x" << std::hex << text_start
              << " - 0x" << text_end << "\n";

    auto section_data_range = pe.getSectionRangeRva(".data");
    if (!section_data_range.first || !section_data_range.second)
    {
        std::cerr << "[ERROR] .data section not found\n";
        return;
    }
    uint64_t data_start = *section_data_range.first;
    uint64_t data_end = *section_data_range.second;
    std::cout << "[INFO] .data range: 0x" << std::hex << data_start
              << " - 0x" << data_end << "\n\n";
    auto list_func_ranges = pe.getFunctionRangesByUnWind();
    // Search for [FGESDK] signature via u8 to hex pattern
    auto offset_sign_text_list = pe.searchDataPatternAll(scanner::helper::u8ToPattern(u8"[FGESDK]"), rdata_start, rdata_end);
    if (offset_sign_text_list.empty())
    {
        std::cout << "[WARN] [FGESDK] not found\n";
        return;
    }
    std::vector<scanner::PeFunctionRange> temp_result_list;
    uint64_t offset_sign_text = offset_sign_text_list[0];
    std::cout << "[debug] offset_sign_text: 0x" << std::hex << std::uppercase
              << (offset_sign_text + pe_image_base) << "\n";

    // Search for xref to [FGESDK]
    auto offset_sign_text_xref_list = pe.searchDataMaybeXrefAll(offset_sign_text, text_start, text_end);
    for (uint64_t offset_sign_text_xref : offset_sign_text_xref_list)
    {

        auto tea_crypt_inner = pe.findFunctionContainingAddress(list_func_ranges, offset_sign_text_xref);
        if (tea_crypt_inner)
        {
            temp_result_list.push_back(tea_crypt_inner.value());
        }
    }

    // Search for type info string via u8 to hex pattern
    auto offset_get_token_vtable_typeinfo_text_list = pe.searchDataPatternAll(
        scanner::helper::u8ToPattern(u8".?AVSSOGetTokenRequest@base@qsec@@"),
        data_start, data_end);

    if (offset_get_token_vtable_typeinfo_text_list.empty())
    {
        std::cout << "[ERROR] Type info string not found in both .data and .rdata sections\n";
        return;
    }

    uint64_t offset_get_token_vtable_typeinfo_text = offset_get_token_vtable_typeinfo_text_list[0];
    std::cout << "[debug] offset_get_token_vtable_typeinfo_text: 0x" << std::hex
              << (offset_get_token_vtable_typeinfo_text + pe_image_base) << "\n";

    // 0x10是8+8的偏移 两个db属性 0x14是被引用元素偏移
    uint64_t offset_get_token_vtable_typeinfo_rva = offset_get_token_vtable_typeinfo_text - 0x10;

    // Convert to little-endian bytes and search
    uint32_t rva_value = static_cast<uint32_t>(offset_get_token_vtable_typeinfo_rva);
    std::string pattern = scanner::helper::le32ToPattern(rva_value);
    auto xref_list = pe.searchDataPatternAll(pattern, rdata_start, rdata_end);

    if (xref_list.empty())
    {
        std::cout << "[ERROR] offset_get_token_vtable_typeinfo_xref not found\n";
        return;
    }

    uint64_t offset_get_token_vtable_typeinfo_xref = xref_list[0] - 0x14;
    std::cout << "[debug] offset_get_token_vtable_typeinfo_xref: 0x" << std::hex
              << (offset_get_token_vtable_typeinfo_xref + pe_image_base) << "\n\n";

    // 搜索 offset_get_token_vtable_typeinfo_xref 被谁引用
    std::cout << "[*] Searching for references to offset_get_token_vtable_typeinfo_xref...\n";
    // 在 .text 段搜索引用
    auto xref_in_text = pe.searchDataMaybeXrefAll(offset_get_token_vtable_typeinfo_xref, text_start, text_end);
    std::cout << "[INFO] Found " << std::dec << xref_in_text.size()
              << " references in .text section\n";

    std::set<uint64_t> unique_funcs;
    for (size_t i = 0; i < xref_in_text.size(); ++i)
    {
        auto func_range = pe.findFunctionContainingAddress(temp_result_list, xref_in_text[i]);
        if (func_range)
        {
            unique_funcs.insert(func_range->start + pe_image_base);
        }
    }

    // 最终结果统一输出
    if (unique_funcs.empty())
    {
        std::cout << "\n[result] No referencing functions found.\n";
        return;
    }
    std::cout << "\n[result] Found " << std::dec << unique_funcs.size() << " unique referencing function(s):\n";
    std::cout << "  0x" << std::hex << std::uppercase << *unique_funcs.begin() << "\n";
}

int main(int argc, char **argv)
{
    std::cout << "=== PE Offset Scanner ===\n\n";

    // 计算运行时间
    auto start = std::chrono::high_resolution_clock::now();
    getOffset("F:\\IDA-Wrapper\\40768\\wrapper.node");
    auto end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> duration = end - start;
    std::cout << "[INFO] Scan completed in " << duration.count() << " seconds\n";

    return 0;
}
