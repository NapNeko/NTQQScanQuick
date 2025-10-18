#include <iostream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <set>
#include "scanner/ElfScanner.h"
#include "scanner/helper.h"

void getOffset(const std::string &elfPath)
{
    std::cout << "\n=== Getting Offsets ===\n";
    std::cout << "Target file: " << elfPath << "\n\n";

    scanner::ElfScanner elf;

    // Load ELF file
    if (!elf.loadFile(elfPath))
    {
        std::cerr << "[ERROR] Failed to load ELF file: " << elfPath << "\n";
        return;
    }

    std::cout << "[INFO] ELF file loaded successfully\n";

    // 获取段范围
    auto section_rodata_range = elf.getSectionRangeRva(".rodata");
    if (!section_rodata_range.first || !section_rodata_range.second)
    {
        std::cerr << "[ERROR] .rodata section not found\n";
        return;
    }
    uint64_t rodata_start = *section_rodata_range.first;
    uint64_t rodata_end = *section_rodata_range.second;
    std::cout << "[INFO] .rodata range: 0x" << std::hex << rodata_start
              << " - 0x" << rodata_end << "\n";

    auto section_text_range = elf.getSectionRangeRva(".text");
    if (!section_text_range.first || !section_text_range.second)
    {
        std::cerr << "[ERROR] .text section not found\n";
        return;
    }
    uint64_t text_start = *section_text_range.first;
    uint64_t text_end = *section_text_range.second;
    std::cout << "[INFO] .text range: 0x" << std::hex << text_start
              << " - 0x" << text_end << "\n";

    auto section_data_range = elf.getSectionRangeRva(".data");
    if (!section_data_range.first || !section_data_range.second)
    {
        std::cerr << "[ERROR] .data section not found\n";
        return;
    }
    uint64_t data_start = *section_data_range.first;
    uint64_t data_end = *section_data_range.second;
    std::cout << "[INFO] .data range: 0x" << std::hex << data_start
              << " - 0x" << data_end << "\n\n";

    // 获取函数范围列表
    auto list_func_ranges = elf.getFunctionRanges();
    std::cout << "[INFO] Found " << std::dec << list_func_ranges.size() << " functions\n\n";

    // Search for signature string via u8 to hex pattern
    auto offset_sign_text_list = elf.searchDataPattern(
        scanner::helper::u8ToPattern(u8"MSFSign failed, module_id:{} data:{}"),
        rodata_start, rodata_end);
    if (!offset_sign_text_list)
    {
        std::cout << "[WARN] Signature string not found in .rodata section\n";
        return;
    }
    std::cout << "[DEBUG] offset_sign_text: 0x" << std::hex << std::uppercase
              << *offset_sign_text_list << "\n";

    auto offset_sign_text_xref = elf.searchDataMaybeXref(*offset_sign_text_list, text_start, text_end);
    if (!offset_sign_text_xref)
    {
        std::cout << "[INFO] No xrefs to signature string found\n";
        return;
    }
    std::cout << "[INFO] Found offset_sign_text_xref: 0x" << std::hex << *offset_sign_text_xref << "\n";
    auto sign_function_out = elf.findFunctionContainingAddress(list_func_ranges, offset_sign_text_xref.value());
    if (!sign_function_out)
    {
        std::cout << "[WARN] No function contains the xref to signature string\n";
        return;
    }
    std::cout << "[INFO] Found sign function: 0x" << std::hex << sign_function_out->start
              << " - 0x" << sign_function_out->end << "\n";
}

int main(int argc, char **argv)
{
    std::cout << "=== ELF Offset Scanner ===\n\n";

    // 计算运行时间
    auto start = std::chrono::high_resolution_clock::now();
    getOffset("F:\\IDA-Wrapper\\40768-amd64\\wrapper.node");
    auto end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> duration = end - start;
    std::cout << "[INFO] Scan completed in " << duration.count() << " seconds\n";

    return 0;
}
