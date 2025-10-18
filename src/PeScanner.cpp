#include "scanner/PeScanner.h"
#include <fstream>
#include <cstring>
#include <algorithm>
#include <sstream>

namespace scanner
{
// PE structures
#pragma pack(push, 1)
    struct IMAGE_DOS_HEADER
    {
        uint16_t e_magic;
        uint16_t e_cblp;
        uint16_t e_cp;
        uint16_t e_crlc;
        uint16_t e_cparhdr;
        uint16_t e_minalloc;
        uint16_t e_maxalloc;
        uint16_t e_ss;
        uint16_t e_sp;
        uint16_t e_csum;
        uint16_t e_ip;
        uint16_t e_cs;
        uint16_t e_lfarlc;
        uint16_t e_ovno;
        uint16_t e_res[4];
        uint16_t e_oemid;
        uint16_t e_oeminfo;
        uint16_t e_res2[10];
        uint32_t e_lfanew;
    };

    struct IMAGE_FILE_HEADER
    {
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
    };

    struct IMAGE_DATA_DIRECTORY
    {
        uint32_t VirtualAddress;
        uint32_t Size;
    };

    struct IMAGE_OPTIONAL_HEADER64
    {
        uint16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        uint64_t ImageBase;
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint64_t SizeOfStackReserve;
        uint64_t SizeOfStackCommit;
        uint64_t SizeOfHeapReserve;
        uint64_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[16];
    };

    struct IMAGE_SECTION_HEADER
    {
        uint8_t Name[8];
        uint32_t VirtualSize;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLinenumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLinenumbers;
        uint32_t Characteristics;
    };

    // x64 异常处理结构 (.pdata 节)
    struct RUNTIME_FUNCTION
    {
        uint32_t BeginAddress;      // RVA of function start
        uint32_t EndAddress;        // RVA of function end
        uint32_t UnwindInfoAddress; // RVA of unwind info
    };
#pragma pack(pop)

    struct PeScanner::Impl
    {
        std::vector<uint8_t> fileData;
        uint64_t imageBase = 0;
        uint32_t peOffset = 0;
        uint16_t numberOfSections = 0;
        uint32_t sectionHeaderOffset = 0;
        std::vector<IMAGE_SECTION_HEADER> sections;
        bool initialized = false;

        ~Impl()
        {
        }

        bool parsePe()
        {
            if (fileData.size() < sizeof(IMAGE_DOS_HEADER))
            {
                return false;
            }

            // Parse DOS header
            auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(&fileData[0]);
            if (dosHeader->e_magic != 0x5A4D) // 'MZ'
            {
                return false;
            }

            peOffset = dosHeader->e_lfanew;
            if (peOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64) > fileData.size())
            {
                return false;
            }

            // Check PE signature
            uint32_t peSignature = *reinterpret_cast<uint32_t *>(&fileData[peOffset]);
            if (peSignature != 0x00004550) // 'PE\0\0'
            {
                return false;
            }

            // Parse COFF header
            auto coffHeader = reinterpret_cast<IMAGE_FILE_HEADER *>(&fileData[peOffset + 4]);
            numberOfSections = coffHeader->NumberOfSections;

            // Parse Optional Header (x64)
            auto optHeader = reinterpret_cast<IMAGE_OPTIONAL_HEADER64 *>(&fileData[peOffset + 4 + sizeof(IMAGE_FILE_HEADER)]);
            if (optHeader->Magic != 0x20B) // PE32+
            {
                return false;
            }
            imageBase = optHeader->ImageBase;

            // Parse section headers
            sectionHeaderOffset = peOffset + 4 + sizeof(IMAGE_FILE_HEADER) + coffHeader->SizeOfOptionalHeader;
            sections.clear();

            for (uint16_t i = 0; i < numberOfSections; i++)
            {
                uint32_t offset = sectionHeaderOffset + i * sizeof(IMAGE_SECTION_HEADER);
                if (offset + sizeof(IMAGE_SECTION_HEADER) > fileData.size())
                {
                    break;
                }
                auto section = reinterpret_cast<IMAGE_SECTION_HEADER *>(&fileData[offset]);
                sections.push_back(*section);
            }

            return true;
        }

        uint64_t rvaToFileOffset(uint64_t rva) const
        {
            for (const auto &section : sections)
            {
                if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.VirtualSize)
                {
                    return rva - section.VirtualAddress + section.PointerToRawData;
                }
            }
            return rva;
        }

        std::string getSectionName(const IMAGE_SECTION_HEADER &section) const
        {
            char name[9] = {0};
            memcpy(name, section.Name, 8);
            return std::string(name);
        }
    };

    PeScanner::PeScanner() : pImpl(std::make_unique<Impl>()) {}

    PeScanner::~PeScanner() = default;

    bool PeScanner::loadFile(const std::string &filePath)
    {
        std::ifstream file(filePath, std::ios::binary);
        if (!file)
        {
            return false;
        }

        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        pImpl->fileData.resize(fileSize);
        file.read(reinterpret_cast<char *>(pImpl->fileData.data()), fileSize);

        pImpl->initialized = pImpl->parsePe();
        return pImpl->initialized;
    }

    std::vector<PeFunctionRange> PeScanner::getFunctionRanges() const
    {
        std::vector<PeFunctionRange> functions;

        if (!pImpl->initialized)
        {
            return functions;
        }

        // Get .text section
        auto textRange = getSectionRangeRva(".text");
        if (!textRange.first || !textRange.second)
        {
            return functions;
        }

        uint64_t textStart = *textRange.first;
        uint64_t textEnd = *textRange.second;
        uint64_t fileOffset = pImpl->rvaToFileOffset(textStart);
        uint64_t size = textEnd - textStart;

        if (fileOffset + size > pImpl->fileData.size())
        {
            return functions;
        }

        std::vector<uint64_t> functionStarts;
        const uint8_t *data = &pImpl->fileData[fileOffset];

        // Find function prologues using byte patterns:
        // push rbp = 55
        // mov rbp, rsp = 48 89 E5
        for (uint64_t i = 0; i < size - 4; i++)
        {
            uint8_t byte0 = data[i];

            // Pattern 1: push rbp; mov rbp, rsp (55 48 89 E5)
            if (byte0 == 0x55)
            {
                if (data[i + 1] == 0x48 &&
                    data[i + 2] == 0x89 &&
                    data[i + 3] == 0xE5)
                {
                    // Search backwards for consecutive push instructions
                    uint64_t start = i;
                    while (start > 0 && data[start - 1] >= 0x50 && data[start - 1] <= 0x57)
                    {
                        start--;
                    }
                    functionStarts.push_back(textStart + start);
                }
            }
            // Pattern 2: just mov rbp, rsp without push rbp
            else if (byte0 == 0x48)
            {
                if (data[i + 1] == 0x89 &&
                    data[i + 2] == 0xE5)
                {
                    functionStarts.push_back(textStart + i);
                }
            }
        }

        // Remove duplicates and sort
        std::sort(functionStarts.begin(), functionStarts.end());
        functionStarts.erase(std::unique(functionStarts.begin(), functionStarts.end()), functionStarts.end());

        // Create function ranges
        for (size_t i = 0; i < functionStarts.size(); i++)
        {
            PeFunctionRange func;
            func.start = functionStarts[i];

            if (i + 1 < functionStarts.size())
            {
                func.end = functionStarts[i + 1];
            }
            else
            {
                func.end = textEnd;
            }

            functions.push_back(func);
        }

        return functions;
    }

    std::vector<PeFunctionRange> PeScanner::getFunctionRangesByUnWind() const
    {
        std::vector<PeFunctionRange> functions;

        if (!pImpl->initialized)
        {
            return functions;
        }

        // Get .pdata section (Exception Directory)
        auto pdataRange = getSectionRangeRva(".pdata");
        if (!pdataRange.first || !pdataRange.second)
        {
            return functions;
        }

        uint64_t pdataStart = *pdataRange.first;
        uint64_t pdataEnd = *pdataRange.second;
        uint64_t pdataSize = pdataEnd - pdataStart;

        // Calculate number of RUNTIME_FUNCTION entries
        size_t entryCount = pdataSize / sizeof(RUNTIME_FUNCTION);

        if (entryCount == 0)
        {
            return functions;
        }

        // Read .pdata section
        uint64_t fileOffset = pImpl->rvaToFileOffset(pdataStart);
        if (fileOffset + pdataSize > pImpl->fileData.size())
        {
            return functions;
        }

        // Parse RUNTIME_FUNCTION entries
        for (size_t i = 0; i < entryCount; i++)
        {
            uint64_t entryOffset = fileOffset + i * sizeof(RUNTIME_FUNCTION);
            if (entryOffset + sizeof(RUNTIME_FUNCTION) > pImpl->fileData.size())
            {
                break;
            }

            auto runtimeFunc = reinterpret_cast<const RUNTIME_FUNCTION *>(
                &pImpl->fileData[entryOffset]);

            // Validate the entry
            if (runtimeFunc->BeginAddress == 0 ||
                runtimeFunc->EndAddress == 0 ||
                runtimeFunc->BeginAddress >= runtimeFunc->EndAddress)
            {
                continue;
            }

            PeFunctionRange func;
            func.start = runtimeFunc->BeginAddress;
            func.end = runtimeFunc->EndAddress;
            functions.push_back(func);
        }

        // Sort by start address
        std::sort(functions.begin(), functions.end(),
                  [](const PeFunctionRange &a, const PeFunctionRange &b)
                  {
                      return a.start < b.start;
                  });

        return functions;
    }

    std::optional<PeFunctionRange> PeScanner::findFunctionContainingAddress(std::vector<scanner::PeFunctionRange> functions, uint64_t address) const
    {
        // 二分查找优化: O(n) -> O(log n)
        auto it = std::upper_bound(functions.begin(), functions.end(), address,
                                   [](uint64_t addr, const PeFunctionRange &func)
                                   {
                                       return addr < func.start;
                                   });

        if (it != functions.begin())
        {
            --it;
            if (it->start <= address && address < it->end)
            {
                return *it;
            }
        }
        return std::nullopt;
    }

    std::pair<std::optional<uint64_t>, std::optional<uint64_t>>
    PeScanner::getSectionRangeRva(const std::string &sectionName) const
    {
        if (!pImpl->initialized)
        {
            return {std::nullopt, std::nullopt};
        }

        // Optimize: compare directly with section name bytes
        size_t nameLen = sectionName.length();
        if (nameLen > 8)
        {
            return {std::nullopt, std::nullopt};
        }

        for (const auto &section : pImpl->sections)
        {
            // Compare directly without creating string
            if (std::memcmp(section.Name, sectionName.c_str(), nameLen) == 0 &&
                (nameLen == 8 || section.Name[nameLen] == '\0'))
            {
                uint64_t start = section.VirtualAddress;
                uint64_t end = section.VirtualAddress + section.VirtualSize;
                return {start, end};
            }
        }
        return {std::nullopt, std::nullopt};
    }

    std::pair<std::optional<uint64_t>, std::optional<uint64_t>>
    PeScanner::getSectionRangeReal(const std::string &sectionName) const
    {
        auto [start, end] = getSectionRangeRva(sectionName);
        if (start && end)
        {
            return {*start + pImpl->imageBase, *end + pImpl->imageBase};
        }
        return {std::nullopt, std::nullopt};
    }

    std::optional<uint64_t> PeScanner::searchBytes(uint64_t start, uint64_t end,
                                                   const std::vector<uint8_t> &bytes) const
    {
        if (!pImpl->initialized || bytes.empty())
        {
            return std::nullopt;
        }

        uint64_t fileStart = pImpl->rvaToFileOffset(start);
        uint64_t fileEnd = pImpl->rvaToFileOffset(end);

        if (fileEnd > pImpl->fileData.size())
        {
            fileEnd = pImpl->fileData.size();
        }

        if (fileStart + bytes.size() > fileEnd)
        {
            return std::nullopt;
        }

        // Direct memory search
        for (uint64_t i = fileStart; i <= fileEnd - bytes.size(); i++)
        {
            if (std::memcmp(&pImpl->fileData[i], bytes.data(), bytes.size()) == 0)
            {
                // Convert file offset back to RVA
                for (const auto &section : pImpl->sections)
                {
                    if (i >= section.PointerToRawData && i < section.PointerToRawData + section.SizeOfRawData)
                    {
                        return i - section.PointerToRawData + section.VirtualAddress;
                    }
                }
            }
        }
        return std::nullopt;
    }

    std::vector<uint64_t> PeScanner::searchBytesAll(uint64_t start, uint64_t end,
                                                    const std::vector<uint8_t> &bytes) const
    {
        std::vector<uint64_t> results;

        if (!pImpl->initialized || bytes.empty())
        {
            return results;
        }

        uint64_t fileStart = pImpl->rvaToFileOffset(start);
        uint64_t fileEnd = pImpl->rvaToFileOffset(end);

        if (fileEnd > pImpl->fileData.size())
        {
            fileEnd = pImpl->fileData.size();
        }

        if (fileStart + bytes.size() > fileEnd)
        {
            return results;
        }

        // Direct memory search
        for (uint64_t i = fileStart; i <= fileEnd - bytes.size(); i++)
        {
            if (std::memcmp(&pImpl->fileData[i], bytes.data(), bytes.size()) == 0)
            {
                // Convert file offset back to RVA
                for (const auto &section : pImpl->sections)
                {
                    if (i >= section.PointerToRawData && i < section.PointerToRawData + section.SizeOfRawData)
                    {
                        results.push_back(i - section.PointerToRawData + section.VirtualAddress);
                        break;
                    }
                }
            }
        }
        return results;
    }

    std::optional<uint64_t> PeScanner::searchDataMaybeXref(uint64_t stringRva,
                                                           uint64_t start, uint64_t end) const
    {
        if (!pImpl->initialized)
        {
            return std::nullopt;
        }

        uint64_t fileStart = pImpl->rvaToFileOffset(start);
        uint64_t fileEnd = pImpl->rvaToFileOffset(end);

        if (fileEnd > pImpl->fileData.size())
        {
            fileEnd = pImpl->fileData.size();
        }

        if (fileStart + 4 > fileEnd)
        {
            return std::nullopt;
        }

        // Find which section we're in for RVA conversion
        const IMAGE_SECTION_HEADER *currentSection = nullptr;
        for (const auto &section : pImpl->sections)
        {
            if (fileStart >= section.PointerToRawData && fileStart < section.PointerToRawData + section.SizeOfRawData)
            {
                currentSection = &section;
                break;
            }
        }

        if (!currentSection)
        {
            return std::nullopt;
        }

        const int32_t *dataPtr = reinterpret_cast<const int32_t *>(pImpl->fileData.data());
        uint64_t sectionBase = currentSection->PointerToRawData;
        uint64_t sectionVirtualBase = currentSection->VirtualAddress;

        for (uint64_t i = fileStart; i <= fileEnd - 4; i++)
        {
            int32_t offset = dataPtr[i / 4];
            uint64_t currentRva = (i - sectionBase) + sectionVirtualBase;
            uint64_t refAddr = currentRva + 4 + offset;

            if (refAddr == stringRva)
            {
                return currentRva;
            }
        }
        return std::nullopt;
    }

    std::vector<uint64_t> PeScanner::searchDataMaybeXrefAll(uint64_t stringRva,
                                                            uint64_t start, uint64_t end) const
    {
        std::vector<uint64_t> results;

        if (!pImpl->initialized)
        {
            return results;
        }

        uint64_t fileStart = pImpl->rvaToFileOffset(start);
        uint64_t fileEnd = pImpl->rvaToFileOffset(end);

        if (fileEnd > pImpl->fileData.size())
        {
            fileEnd = pImpl->fileData.size();
        }

        if (fileStart + 4 > fileEnd)
        {
            return results;
        }

        // Find which section we're in for RVA conversion
        const IMAGE_SECTION_HEADER *currentSection = nullptr;
        for (const auto &section : pImpl->sections)
        {
            if (fileStart >= section.PointerToRawData && fileStart < section.PointerToRawData + section.SizeOfRawData)
            {
                currentSection = &section;
                break;
            }
        }

        if (!currentSection)
        {
            return results;
        }

        const int32_t *dataPtr = reinterpret_cast<const int32_t *>(pImpl->fileData.data());
        uint64_t sectionBase = currentSection->PointerToRawData;
        uint64_t sectionVirtualBase = currentSection->VirtualAddress;

        for (uint64_t i = fileStart; i <= fileEnd - 4; i++)
        {
            int32_t offset = dataPtr[i / 4];
            uint64_t currentRva = (i - sectionBase) + sectionVirtualBase;
            uint64_t refAddr = currentRva + 4 + offset;

            if (refAddr == stringRva)
            {
                results.push_back(currentRva);
            }
        }
        return results;
    }

    std::optional<uint64_t> PeScanner::searchCallMaybeXref(uint64_t targetRva,
                                                           uint64_t start, uint64_t end) const
    {
        if (!pImpl->initialized)
        {
            return std::nullopt;
        }

        uint64_t fileStart = pImpl->rvaToFileOffset(start);
        uint64_t fileEnd = pImpl->rvaToFileOffset(end);

        if (fileEnd > pImpl->fileData.size())
        {
            fileEnd = pImpl->fileData.size();
        }

        if (fileStart + 5 > fileEnd)
        {
            return std::nullopt;
        }

        // Find which section we're in for RVA conversion
        const IMAGE_SECTION_HEADER *currentSection = nullptr;
        for (const auto &section : pImpl->sections)
        {
            if (fileStart >= section.PointerToRawData && fileStart < section.PointerToRawData + section.SizeOfRawData)
            {
                currentSection = &section;
                break;
            }
        }

        if (!currentSection)
        {
            return std::nullopt;
        }

        const uint8_t *dataPtr = pImpl->fileData.data();
        uint64_t sectionBase = currentSection->PointerToRawData;
        uint64_t sectionVirtualBase = currentSection->VirtualAddress;

        // Search for call instructions (E8 xx xx xx xx - relative call)
        for (uint64_t i = fileStart; i <= fileEnd - 5; i++)
        {
            // Quick check: only process if it's a call opcode
            if (dataPtr[i] != 0xE8)
            {
                continue;
            }

            int32_t offset = *reinterpret_cast<const int32_t *>(&dataPtr[i + 1]);
            uint64_t currentRva = (i - sectionBase) + sectionVirtualBase;
            uint64_t callTarget = currentRva + 5 + offset; // 5 = instruction length

            if (callTarget == targetRva)
            {
                return currentRva;
            }
        }

        return std::nullopt;
    }

    std::optional<uint64_t> PeScanner::searchDataPattern(const std::string &pattern,
                                                         uint64_t start, uint64_t end) const
    {
        auto results = searchDataPatternAll(pattern, start, end);
        if (!results.empty())
        {
            return results[0];
        }
        return std::nullopt;
    }

    std::vector<uint64_t> PeScanner::searchDataPatternAll(const std::string &pattern,
                                                          uint64_t start, uint64_t end) const
    {
        std::vector<uint64_t> results;

        if (!pImpl->initialized || pattern.empty())
        {
            return results;
        }

        // Parse pattern string (e.g., "B9 79 37 9E" or "48 8B ?? 48 89 ??")
        std::vector<uint8_t> patternBytes;
        std::vector<bool> wildcards;

        std::istringstream iss(pattern);
        std::string token;
        while (iss >> token)
        {
            if (token == "?" || token == "??")
            {
                patternBytes.push_back(0);
                wildcards.push_back(true);
            }
            else
            {
                try
                {
                    patternBytes.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
                    wildcards.push_back(false);
                }
                catch (...)
                {
                    return results;
                }
            }
        }

        if (patternBytes.empty())
        {
            return results;
        }

        // Convert RVA to file offset
        uint64_t fileStart = pImpl->rvaToFileOffset(start);
        uint64_t fileEnd = pImpl->rvaToFileOffset(end);

        if (fileEnd > pImpl->fileData.size())
        {
            fileEnd = pImpl->fileData.size();
        }

        if (fileStart + patternBytes.size() > fileEnd)
        {
            return results;
        }

        // Find which section we're in for faster RVA conversion
        const IMAGE_SECTION_HEADER *currentSection = nullptr;
        for (const auto &section : pImpl->sections)
        {
            if (fileStart >= section.PointerToRawData && fileStart < section.PointerToRawData + section.SizeOfRawData)
            {
                currentSection = &section;
                break;
            }
        }

        if (!currentSection)
        {
            return results;
        }

        // Optimize: pre-calculate first byte to search for (skip wildcards at start)
        size_t firstNonWildcard = 0;
        for (size_t i = 0; i < wildcards.size(); i++)
        {
            if (!wildcards[i])
            {
                firstNonWildcard = i;
                break;
            }
        }

        const uint8_t *dataPtr = pImpl->fileData.data();
        uint64_t searchEnd = fileEnd - patternBytes.size();

        // Search for pattern
        for (uint64_t i = fileStart; i <= searchEnd; i++)
        {
            // Quick first-byte check
            if (dataPtr[i + firstNonWildcard] != patternBytes[firstNonWildcard])
            {
                continue;
            }

            // Full pattern match
            bool match = true;
            for (size_t j = 0; j < patternBytes.size(); j++)
            {
                if (!wildcards[j] && dataPtr[i + j] != patternBytes[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                // Convert file offset back to RVA
                uint64_t rva = i - currentSection->PointerToRawData + currentSection->VirtualAddress;
                results.push_back(rva);
            }
        }

        return results;
    }

    std::vector<uint64_t> PeScanner::typeinfoScanAll(uint64_t stringRva,
                                                     uint64_t start, uint64_t end) const
    {
        return searchDataMaybeXrefAll(stringRva, start, end);
    }

    std::vector<uint64_t> PeScanner::getAllCallRange(uint64_t start, uint64_t end) const
    {
        std::vector<uint64_t> callList;

        if (!pImpl->initialized)
        {
            return callList;
        }

        uint64_t fileStart = pImpl->rvaToFileOffset(start);
        uint64_t fileEnd = pImpl->rvaToFileOffset(end);

        if (fileEnd > pImpl->fileData.size())
        {
            fileEnd = pImpl->fileData.size();
        }

        if (fileStart + 5 > fileEnd)
        {
            return callList;
        }

        // Find which section we're in for RVA conversion
        const IMAGE_SECTION_HEADER *currentSection = nullptr;
        for (const auto &section : pImpl->sections)
        {
            if (fileStart >= section.PointerToRawData && fileStart < section.PointerToRawData + section.SizeOfRawData)
            {
                currentSection = &section;
                break;
            }
        }

        if (!currentSection)
        {
            return callList;
        }

        const uint8_t *dataPtr = pImpl->fileData.data();
        uint64_t sectionBase = currentSection->PointerToRawData;
        uint64_t sectionVirtualBase = currentSection->VirtualAddress;

        // Search for call instructions (E8 xx xx xx xx - relative call)
        for (uint64_t i = fileStart; i <= fileEnd - 5; i++)
        {
            // Quick check: only process if it's a call opcode
            if (dataPtr[i] != 0xE8)
            {
                continue;
            }

            // Read the offset and calculate target
            int32_t offset = *reinterpret_cast<const int32_t *>(&dataPtr[i + 1]);
            uint64_t currentRva = (i - sectionBase) + sectionVirtualBase;
            uint64_t callTarget = currentRva + 5 + offset; // 5 = instruction length

            callList.push_back(callTarget);
        }

        return callList;
    }

    std::vector<uint8_t> PeScanner::getData(uint64_t rva, size_t size) const
    {
        if (!pImpl->initialized)
        {
            return std::vector<uint8_t>();
        }

        uint64_t fileOffset = pImpl->rvaToFileOffset(rva);

        if (fileOffset + size > pImpl->fileData.size())
        {
            return std::vector<uint8_t>();
        }

        return std::vector<uint8_t>(
            pImpl->fileData.begin() + fileOffset,
            pImpl->fileData.begin() + fileOffset + size);
    }

    uint64_t PeScanner::getImageBase() const
    {
        return pImpl->imageBase;
    }

} // namespace scanner
