#include <iostream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include "scanner/ElfScanner.h"
#include "scanner/ElfScannerArm64.h"
#include "scanner/PeScanner.h"

// TEA Encryption/Decryption Function Scanner
void scanTeaCryptFunctions(const std::string &pePath)
{
    std::cout << "\n=== Scanning TEA Crypt Functions ===\n";
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

    // Get section ranges
    auto rdata_range = pe.getSectionRangeRva(".rdata");
    if (!rdata_range.first || !rdata_range.second)
    {
        std::cerr << "[WARNING] .rdata section not found\n";
    }
    else
    {
        std::cout << "[INFO] .rdata range: 0x" << std::hex << *rdata_range.first
                  << " - 0x" << *rdata_range.second << "\n";
    }

    auto text_range = pe.getSectionRangeRva(".text");
    if (!text_range.first || !text_range.second)
    {
        std::cerr << "[ERROR] .text section not found\n";
        return;
    }

    uint64_t text_start = *text_range.first;
    uint64_t text_end = *text_range.second;
    std::cout << "[INFO] .text range: 0x" << std::hex << text_start
              << " - 0x" << text_end << "\n\n";

    // Get function ranges
    auto list_func_ranges = pe.getFunctionRangesByUnWind();
    std::cout << "[INFO] Found " << std::dec << list_func_ranges.size() << " functions\n\n";

    std::cout << "[]----------[]\n";

    // ========== Search TEA Encryption Functions ==========
    // delta = 0x9E3779B9 little-endian: B9 79 37 9E
    std::cout << "[*] Searching for TEA encryption functions (delta = 0x9E3779B9)...\n";
    auto list_tea_delta = pe.searchDataPatternAll("B9 79 37 9E", text_start, text_end);
    std::cout << "[INFO] Found " << std::dec << list_tea_delta.size() << " delta patterns\n";

    std::vector<uint64_t> list_inner_crypt;
    std::vector<uint64_t> list_tea_crypt_outer;

    for (uint64_t tea_delta : list_tea_delta)
    {
        auto tea_crypt_inner = pe.findFunctionContainingAddress(list_func_ranges, tea_delta);
        if (tea_crypt_inner)
        {
            // Check if already processed
            if (std::find(list_inner_crypt.begin(), list_inner_crypt.end(),
                          tea_crypt_inner->start) != list_inner_crypt.end())
            {
                continue;
            }

            list_inner_crypt.push_back(tea_crypt_inner->start);
            std::cout << "[debug] Maybe TEA Crypt Inner: 0x" << std::hex << std::uppercase
                      << (tea_crypt_inner->start + pe_image_base) << "\n";

            // Search for calls to this function
            auto tea_crypt_outer = pe.searchCallMaybeXref(tea_crypt_inner->start, text_start, text_end);
            if (tea_crypt_outer)
            {
                std::cout << "[debug] Maybe TEA Crypt Inner Xref: 0x" << std::hex
                          << (*tea_crypt_outer + pe_image_base) << "\n";

                auto tea_crypt_outer_func = pe.findFunctionContainingAddress(list_func_ranges, *tea_crypt_outer);
                if (tea_crypt_outer_func)
                {
                    std::cout << "[result] TEA Crypt Outer: 0x" << std::hex
                              << (tea_crypt_outer_func->start + pe_image_base) << "\n";
                    list_tea_crypt_outer.push_back(tea_crypt_outer_func->start);
                }
            }
        }
    }

    std::cout << "[]----------[]\n\n";

    // ========== Search TEA Decryption Functions ==========
    // sum = 0xE3779B90 little-endian: 90 9B 77 E3
    std::cout << "[*] Searching for TEA decryption functions (sum = 0xE3779B90)...\n";
    auto list_tea_sum = pe.searchDataPatternAll("90 9B 77 E3", text_start, text_end);
    std::cout << "[INFO] Found " << std::dec << list_tea_sum.size() << " sum patterns\n";

    std::vector<uint64_t> list_inner_decrypt;
    std::vector<uint64_t> list_tea_decrypt_outer;

    for (uint64_t tea_sum : list_tea_sum)
    {
        auto tea_decrypt_inner = pe.findFunctionContainingAddress(list_func_ranges,tea_sum);
        if (tea_decrypt_inner)
        {
            // Check if already processed
            if (std::find(list_inner_decrypt.begin(), list_inner_decrypt.end(),
                          tea_decrypt_inner->start) != list_inner_decrypt.end())
            {
                continue;
            }

            list_inner_decrypt.push_back(tea_decrypt_inner->start);
            std::cout << "[debug] Maybe TEA Decrypt Inner: 0x" << std::hex << std::uppercase
                      << (tea_decrypt_inner->start + pe_image_base) << "\n";

            // Search for calls to this function
            auto tea_decrypt_outer = pe.searchCallMaybeXref(tea_decrypt_inner->start, text_start, text_end);
            if (tea_decrypt_outer)
            {
                std::cout << "[debug] Maybe TEA Decrypt Inner Xref: 0x" << std::hex
                          << (*tea_decrypt_outer + pe_image_base) << "\n";

                auto tea_decrypt_outer_func = pe.findFunctionContainingAddress(list_func_ranges, *tea_decrypt_outer);
                if (tea_decrypt_outer_func)
                {
                    std::cout << "[result] TEA Decrypt Outer: 0x" << std::hex
                              << (tea_decrypt_outer_func->start + pe_image_base) << "\n";
                    list_tea_decrypt_outer.push_back(tea_decrypt_outer_func->start);
                }
            }
        }
    }

    std::cout << "[]----------[]\n\n";

    // Output summary
    std::cout << "=== Summary ===\n";
    std::cout << "TEA Encryption Functions Found: " << std::dec << list_tea_crypt_outer.size() << "\n";
    for (size_t i = 0; i < list_tea_crypt_outer.size(); ++i)
    {
        std::cout << "  [" << (i + 1) << "] 0x" << std::hex << std::uppercase
                  << (list_tea_crypt_outer[i] + pe_image_base) << "\n";
    }

    std::cout << "\nTEA Decryption Functions Found: " << std::dec << list_tea_decrypt_outer.size() << "\n";
    for (size_t i = 0; i < list_tea_decrypt_outer.size(); ++i)
    {
        std::cout << "  [" << (i + 1) << "] 0x" << std::hex << std::uppercase
                  << (list_tea_decrypt_outer[i] + pe_image_base) << "\n";
    }
    std::cout << "\n";
}

int main(int argc, char **argv)
{
    std::cout << "=== PE TEA Scanner ===\n\n";
    // 计算运行时间
    auto start = std::chrono::high_resolution_clock::now();
    scanTeaCryptFunctions("F:\\IDA-Wrapper\\40768\\wrapper.node");
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::cout << "[INFO] Scan completed in " << duration.count() << " seconds\n";
    return 0;
}
