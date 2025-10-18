#include "scanner/ElfScanner.h"
#include <fstream>
#include <algorithm>
#include <cstring>
#include <map>

namespace scanner
{

// ELF64 structures
#pragma pack(push, 1)
    struct Elf64_Ehdr
    {
        uint8_t e_ident[16];
        uint16_t e_type;
        uint16_t e_machine;
        uint32_t e_version;
        uint64_t e_entry;
        uint64_t e_phoff;
        uint64_t e_shoff;
        uint32_t e_flags;
        uint16_t e_ehsize;
        uint16_t e_phentsize;
        uint16_t e_phnum;
        uint16_t e_shentsize;
        uint16_t e_shnum;
        uint16_t e_shstrndx;
    };

    struct Elf64_Shdr
    {
        uint32_t sh_name;
        uint32_t sh_type;
        uint64_t sh_flags;
        uint64_t sh_addr;
        uint64_t sh_offset;
        uint64_t sh_size;
        uint32_t sh_link;
        uint32_t sh_info;
        uint64_t sh_addralign;
        uint64_t sh_entsize;
    };
#pragma pack(pop)

    // Section info structure
    struct SectionInfo
    {
        std::string name;
        uint64_t address;
        uint64_t size;
        uint64_t offset;
    };

    // PIMPL implementation
    struct ElfScanner::Impl
    {
        std::vector<uint8_t> fileData;
        std::vector<SectionInfo> sections;
        bool initialized = false;
        std::vector<FunctionRange> functionRanges; // Cached function ranges

        ~Impl()
        {
        }

        bool parseElf()
        {
            if (fileData.size() < sizeof(Elf64_Ehdr))
            {
                return false;
            }

            // Parse ELF header
            auto elfHeader = reinterpret_cast<Elf64_Ehdr *>(&fileData[0]);

            // Check ELF magic
            if (elfHeader->e_ident[0] != 0x7F ||
                elfHeader->e_ident[1] != 'E' ||
                elfHeader->e_ident[2] != 'L' ||
                elfHeader->e_ident[3] != 'F')
            {
                return false;
            }

            // Check for 64-bit ELF
            if (elfHeader->e_ident[4] != 2)
            { // ELFCLASS64
                return false;
            }

            uint64_t e_shoff = elfHeader->e_shoff;
            uint16_t e_shentsize = elfHeader->e_shentsize;
            uint16_t e_shnum = elfHeader->e_shnum;
            uint16_t e_shstrndx = elfHeader->e_shstrndx;

            if (e_shoff == 0 || e_shnum == 0)
            {
                return false;
            }

            // Read section header string table
            if (e_shstrndx >= e_shnum)
            {
                return false;
            }

            uint64_t shstrtab_offset = e_shoff + e_shstrndx * e_shentsize;
            if (shstrtab_offset + sizeof(Elf64_Shdr) > fileData.size())
            {
                return false;
            }

            auto shstrtab_hdr = reinterpret_cast<Elf64_Shdr *>(&fileData[shstrtab_offset]);
            uint64_t strtab_offset = shstrtab_hdr->sh_offset;
            uint64_t strtab_size = shstrtab_hdr->sh_size;

            if (strtab_offset + strtab_size > fileData.size())
            {
                return false;
            }

            // Parse all sections
            sections.clear();
            for (uint16_t i = 0; i < e_shnum; i++)
            {
                uint64_t sh_offset = e_shoff + i * e_shentsize;
                if (sh_offset + sizeof(Elf64_Shdr) > fileData.size())
                {
                    continue;
                }

                auto section = reinterpret_cast<Elf64_Shdr *>(&fileData[sh_offset]);

                // Get section name
                if (section->sh_name >= strtab_size)
                {
                    continue;
                }

                const char *namePtr = reinterpret_cast<const char *>(
                    &fileData[strtab_offset + section->sh_name]);
                std::string sectionName(namePtr);

                // Save all sections for searching
                SectionInfo sectionInfo;
                sectionInfo.name = sectionName;
                sectionInfo.address = section->sh_addr;
                sectionInfo.size = section->sh_size;
                sectionInfo.offset = section->sh_offset;
                sections.push_back(sectionInfo);
            }

            return true;
        }

        std::string getSectionName(const SectionInfo &section) const
        {
            return section.name;
        }

        // 读取ULEB128编码的值
        uint64_t readULEB128(const uint8_t *&ptr, const uint8_t *end)
        {
            uint64_t result = 0;
            int shift = 0;
            while (ptr < end)
            {
                uint8_t byte = *ptr++;
                result |= static_cast<uint64_t>(byte & 0x7F) << shift;
                if ((byte & 0x80) == 0)
                {
                    break;
                }
                shift += 7;
            }
            return result;
        }

        // 读取SLEB128编码的值
        int64_t readSLEB128(const uint8_t *&ptr, const uint8_t *end)
        {
            int64_t result = 0;
            int shift = 0;
            uint8_t byte;
            while (ptr < end)
            {
                byte = *ptr++;
                result |= static_cast<int64_t>(byte & 0x7F) << shift;
                shift += 7;
                if ((byte & 0x80) == 0)
                {
                    break;
                }
            }
            // 符号扩展
            if (shift < 64 && (byte & 0x40))
            {
                result |= -(1LL << shift);
            }
            return result;
        }

        // 读取编码的指针值
        uint64_t readEncodedPointer(const uint8_t *&ptr, const uint8_t *end,
                                    uint8_t encoding, uint64_t baseAddr)
        {
            if (encoding == 0xFF)
            { // DW_EH_PE_omit
                return 0;
            }

            uint64_t result = 0;
            const uint8_t *startPtr = ptr;

            // 读取值
            switch (encoding & 0x0F)
            {
            case 0x00: // DW_EH_PE_absptr
                if (ptr + 8 <= end)
                {
                    std::memcpy(&result, ptr, 8);
                    ptr += 8;
                }
                break;
            case 0x01: // DW_EH_PE_uleb128
                result = readULEB128(ptr, end);
                break;
            case 0x02: // DW_EH_PE_udata2
                if (ptr + 2 <= end)
                {
                    std::memcpy(&result, ptr, 2);
                    ptr += 2;
                }
                break;
            case 0x03: // DW_EH_PE_udata4
                if (ptr + 4 <= end)
                {
                    std::memcpy(&result, ptr, 4);
                    ptr += 4;
                }
                break;
            case 0x04: // DW_EH_PE_udata8
                if (ptr + 8 <= end)
                {
                    std::memcpy(&result, ptr, 8);
                    ptr += 8;
                }
                break;
            case 0x09: // DW_EH_PE_sleb128
                result = static_cast<uint64_t>(readSLEB128(ptr, end));
                break;
            case 0x0A: // DW_EH_PE_sdata2
                if (ptr + 2 <= end)
                {
                    int16_t val;
                    std::memcpy(&val, ptr, 2);
                    result = static_cast<uint64_t>(val);
                    ptr += 2;
                }
                break;
            case 0x0B: // DW_EH_PE_sdata4
                if (ptr + 4 <= end)
                {
                    int32_t val;
                    std::memcpy(&val, ptr, 4);
                    result = static_cast<uint64_t>(val);
                    ptr += 4;
                }
                break;
            case 0x0C: // DW_EH_PE_sdata8
                if (ptr + 8 <= end)
                {
                    int64_t val;
                    std::memcpy(&val, ptr, 8);
                    result = static_cast<uint64_t>(val);
                    ptr += 8;
                }
                break;
            default:
                return 0;
            }

            // 应用相对地址修正
            switch (encoding & 0x70)
            {
            case 0x00: // DW_EH_PE_absptr
                break;
            case 0x10: // DW_EH_PE_pcrel
                result += baseAddr + (startPtr - fileData.data());
                break;
            case 0x20: // DW_EH_PE_textrel
            case 0x30: // DW_EH_PE_datarel
            case 0x40: // DW_EH_PE_funcrel
            case 0x50: // DW_EH_PE_aligned
                // 暂不支持这些编码方式
                break;
            }

            return result;
        }

        // Parse .eh_frame section to extract function ranges
        void parseEhFrame()
        {
            functionRanges.clear();

            // Find .eh_frame section
            const SectionInfo *ehFrameSection = nullptr;
            for (const auto &section : sections)
            {
                if (section.name == ".eh_frame")
                {
                    ehFrameSection = &section;
                    break;
                }
            }

            if (!ehFrameSection || ehFrameSection->size == 0)
            {
                return;
            }

            if (ehFrameSection->offset + ehFrameSection->size > fileData.size())
            {
                return;
            }

            const uint8_t *ptr = &fileData[ehFrameSection->offset];
            const uint8_t *end = ptr + ehFrameSection->size;
            // For pc-relative addressing, baseAddr should be the conversion factor:
            // virtual_address = baseAddr + file_offset
            uint64_t baseAddr = ehFrameSection->address - ehFrameSection->offset;

            // Store CIE information: offset -> fde_encoding
            std::map<uint64_t, uint8_t> cieEncodings;

            while (ptr < end)
            {
                const uint8_t *entryStart = ptr;
                uint64_t entryOffset = entryStart - &fileData[ehFrameSection->offset];

                // Read length field
                if (ptr + 4 > end)
                    break;
                uint32_t length;
                std::memcpy(&length, ptr, 4);
                ptr += 4;

                if (length == 0)
                    break; // Terminator

                // Check for extended length
                bool is64bit = false;
                if (length == 0xFFFFFFFF)
                {
                    if (ptr + 8 > end)
                        break;
                    uint64_t length64;
                    std::memcpy(&length64, ptr, 8);
                    ptr += 8;
                    length = static_cast<uint32_t>(length64);
                    is64bit = true;
                }

                const uint8_t *entryEnd = ptr + length;
                if (entryEnd > end)
                    break;

                // Read CIE ID
                uint32_t cieId;
                std::memcpy(&cieId, ptr, 4);
                ptr += 4;

                if (cieId == 0)
                {
                    // This is a CIE (Common Information Entry)
                    // Parse CIE to get FDE encoding
                    if (ptr >= entryEnd)
                    {
                        ptr = entryEnd;
                        continue;
                    }

                    uint8_t version = *ptr++;
                    
                    // Read augmentation string
                    std::string augmentation;
                    while (ptr < entryEnd && *ptr != 0)
                    {
                        augmentation += static_cast<char>(*ptr++);
                    }
                    if (ptr < entryEnd)
                        ptr++; // skip null terminator

                    // Default encoding
                    uint8_t fdeEncoding = 0x1B; // DW_EH_PE_pcrel | DW_EH_PE_sdata4

                    // Skip code alignment factor, data alignment factor, return address register
                    if (ptr < entryEnd)
                    {
                        readULEB128(ptr, entryEnd); // code_alignment_factor
                    }
                    if (ptr < entryEnd)
                    {
                        readSLEB128(ptr, entryEnd); // data_alignment_factor
                    }
                    if (ptr < entryEnd)
                    {
                        if (version == 1)
                        {
                            ptr++; // return_address_register
                        }
                        else
                        {
                            readULEB128(ptr, entryEnd); // return_address_register
                        }
                    }

                    // Parse augmentation data if present
                    if (!augmentation.empty() && augmentation[0] == 'z')
                    {
                        if (ptr < entryEnd)
                        {
                            uint64_t augDataLen = readULEB128(ptr, entryEnd);
                            const uint8_t *augDataEnd = ptr + augDataLen;
                            if (augDataEnd > entryEnd)
                                augDataEnd = entryEnd;

                            // Parse augmentation string
                            for (size_t i = 1; i < augmentation.size() && ptr < augDataEnd; i++)
                            {
                                if (augmentation[i] == 'R')
                                {
                                    // FDE encoding
                                    fdeEncoding = *ptr++;
                                }
                                else if (augmentation[i] == 'L')
                                {
                                    // LSDA encoding
                                    ptr++;
                                }
                                else if (augmentation[i] == 'P')
                                {
                                    // Personality encoding
                                    uint8_t persEncoding = *ptr++;
                                    readEncodedPointer(ptr, augDataEnd, persEncoding, baseAddr);
                                }
                            }
                        }
                    }

                    // Store CIE encoding
                    cieEncodings[entryOffset] = fdeEncoding;
                    ptr = entryEnd;
                    continue;
                }

                // This is an FDE (Frame Description Entry)
                // Find corresponding CIE
                uint64_t cieOffset = entryOffset + 4 - cieId;
                uint8_t fdeEncoding = 0x1B; // default
                
                auto it = cieEncodings.find(cieOffset);
                if (it != cieEncodings.end())
                {
                    fdeEncoding = it->second;
                }

                // Read PC begin (function start address)
                // baseAddr already contains the conversion factor for pc-relative addressing
                const uint8_t *pcBeginPtr = ptr;
                uint64_t pcBegin = readEncodedPointer(ptr, entryEnd, fdeEncoding, baseAddr);

                // Read PC range (function size)
                uint64_t pcRange = readEncodedPointer(ptr, entryEnd, fdeEncoding & 0x0F, 0);

                if (pcBegin > 0 && pcRange > 0)
                {
                    FunctionRange range;
                    range.start = pcBegin;
                    range.end = pcBegin + pcRange;
                    functionRanges.push_back(range);
                }

                ptr = entryEnd;
            }

            // Sort by start address
            std::sort(functionRanges.begin(), functionRanges.end(),
                      [](const FunctionRange &a, const FunctionRange &b)
                      {
                          return a.start < b.start;
                      });
        }
    };

    ElfScanner::ElfScanner() : pImpl(std::make_unique<Impl>()) {}

    ElfScanner::~ElfScanner() = default;

    bool ElfScanner::loadFile(const std::string &filePath)
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

        pImpl->initialized = pImpl->parseElf();

        // Parse .eh_frame section to get function ranges
        if (pImpl->initialized)
        {
            pImpl->parseEhFrame();
        }

        return pImpl->initialized;
    }

    std::vector<FunctionRange> ElfScanner::getFunctionRanges() const
    {
        if (!pImpl->initialized)
        {
            return std::vector<FunctionRange>();
        }

        // 直接返回从 .eh_frame 解析得到的函数范围
        return pImpl->functionRanges;
    }

    std::optional<FunctionRange> ElfScanner::findFunctionContainingAddress(std::vector<scanner::FunctionRange> functions, uint64_t address) const
    {
        for (const auto &func : functions)
        {
            if (func.start <= address && address < func.end)
            {
                return func;
            }
        }
        return std::nullopt;
    }

    std::pair<std::optional<uint64_t>, std::optional<uint64_t>>
    ElfScanner::getSectionRangeRva(const std::string &sectionName) const
    {
        if (!pImpl->initialized)
        {
            return {std::nullopt, std::nullopt};
        }

        for (const auto &section : pImpl->sections)
        {
            if (section.name == sectionName)
            {
                return {section.address, section.address + section.size};
            }
        }
        return {std::nullopt, std::nullopt};
    }

    std::optional<uint64_t> ElfScanner::searchBytes(uint64_t start, uint64_t end,
                                                    const std::vector<uint8_t> &bytes) const
    {
        if (!pImpl->initialized || bytes.empty())
        {
            return std::nullopt;
        }

        for (const auto &section : pImpl->sections)
        {
            if (section.address <= start && start < section.address + section.size)
            {
                if (section.offset + section.size > pImpl->fileData.size())
                {
                    continue;
                }

                size_t sectionStart = start - section.address;
                size_t searchLen = std::min(end - start, section.size - sectionStart);

                const uint8_t *sectionData = &pImpl->fileData[section.offset];

                for (size_t i = sectionStart; i <= sectionStart + searchLen - bytes.size(); i++)
                {
                    if (std::memcmp(&sectionData[i], bytes.data(), bytes.size()) == 0)
                    {
                        return section.address + i;
                    }
                }
            }
        }
        return std::nullopt;
    }

    std::vector<uint64_t> ElfScanner::searchBytesAll(uint64_t start, uint64_t end,
                                                     const std::vector<uint8_t> &bytes) const
    {
        std::vector<uint64_t> results;

        if (!pImpl->initialized || bytes.empty())
        {
            return results;
        }

        for (const auto &section : pImpl->sections)
        {
            if (section.address <= start && start < section.address + section.size)
            {
                if (section.offset + section.size > pImpl->fileData.size())
                {
                    continue;
                }

                size_t sectionStart = start - section.address;
                size_t searchLen = std::min(end - start, section.size - sectionStart);

                const uint8_t *sectionData = &pImpl->fileData[section.offset];

                for (size_t i = sectionStart; i <= sectionStart + searchLen - bytes.size(); i++)
                {
                    if (std::memcmp(&sectionData[i], bytes.data(), bytes.size()) == 0)
                    {
                        results.push_back(section.address + i);
                    }
                }
            }
        }
        return results;
    }

    std::optional<uint64_t> ElfScanner::searchDataPattern(const std::string &pattern,
                                                          uint64_t start, uint64_t end) const
    {
        if (!pImpl->initialized)
        {
            return std::nullopt;
        }

        std::string cleanPattern = pattern;
        cleanPattern.erase(std::remove(cleanPattern.begin(), cleanPattern.end(), ' '), cleanPattern.end());
        std::transform(cleanPattern.begin(), cleanPattern.end(), cleanPattern.begin(), ::tolower);

        for (const auto &section : pImpl->sections)
        {
            if (section.address <= start && start < section.address + section.size)
            {
                if (section.offset + section.size > pImpl->fileData.size())
                {
                    continue;
                }

                size_t sectionStart = start - section.address;
                size_t searchLen = std::min(end - start, section.size - sectionStart);
                size_t patternLen = cleanPattern.length() / 2;

                const uint8_t *sectionData = &pImpl->fileData[section.offset];

                for (size_t i = sectionStart; i <= sectionStart + searchLen - patternLen; i++)
                {
                    bool match = true;
                    for (size_t j = 0; j < cleanPattern.length(); j++)
                    {
                        if (cleanPattern[j] == '?')
                        {
                            continue;
                        }

                        char hexChar = cleanPattern[j];
                        uint8_t byte = sectionData[i + j / 2];
                        char byteHex = (j % 2 == 0) ? ((byte >> 4) & 0xF) : (byte & 0xF);
                        byteHex += (byteHex < 10) ? '0' : ('a' - 10);

                        if (hexChar != byteHex)
                        {
                            match = false;
                            break;
                        }
                    }

                    if (match)
                    {
                        return section.address + i;
                    }
                }
            }
        }
        return std::nullopt;
    }

    std::vector<uint64_t> ElfScanner::searchDataPatternAll(const std::string &pattern,
                                                           uint64_t start, uint64_t end) const
    {
        std::vector<uint64_t> results;

        if (!pImpl->initialized)
        {
            return results;
        }

        std::string cleanPattern = pattern;
        cleanPattern.erase(std::remove(cleanPattern.begin(), cleanPattern.end(), ' '), cleanPattern.end());
        std::transform(cleanPattern.begin(), cleanPattern.end(), cleanPattern.begin(), ::tolower);

        for (const auto &section : pImpl->sections)
        {
            if (section.address <= start && start < section.address + section.size)
            {
                if (section.offset + section.size > pImpl->fileData.size())
                {
                    continue;
                }

                size_t sectionStart = start - section.address;
                size_t searchLen = std::min(end - start, section.size - sectionStart);
                size_t patternLen = cleanPattern.length() / 2;

                const uint8_t *sectionData = &pImpl->fileData[section.offset];

                for (size_t i = sectionStart; i <= sectionStart + searchLen - patternLen; i++)
                {
                    bool match = true;
                    for (size_t j = 0; j < cleanPattern.length(); j++)
                    {
                        if (cleanPattern[j] == '?')
                        {
                            continue;
                        }

                        char hexChar = cleanPattern[j];
                        uint8_t byte = sectionData[i + j / 2];
                        char byteHex = (j % 2 == 0) ? ((byte >> 4) & 0xF) : (byte & 0xF);
                        byteHex += (byteHex < 10) ? '0' : ('a' - 10);

                        if (hexChar != byteHex)
                        {
                            match = false;
                            break;
                        }
                    }

                    if (match)
                    {
                        results.push_back(section.address + i);
                    }
                }
            }
        }
        return results;
    }

    std::optional<uint64_t> ElfScanner::searchDataMaybeXref(uint64_t targetAddr,
                                                            uint64_t start, uint64_t end) const
    {
        if (!pImpl->initialized)
        {
            return std::nullopt;
        }

        for (const auto &section : pImpl->sections)
        {
            if (section.address <= start && start < section.address + section.size)
            {
                if (section.offset + section.size > pImpl->fileData.size())
                {
                    continue;
                }

                size_t sectionStart = start - section.address;
                size_t searchLen = std::min(end - start, section.size - sectionStart);

                const uint8_t *sectionData = &pImpl->fileData[section.offset];

                for (size_t i = sectionStart; i <= sectionStart + searchLen - 4; i++)
                {
                    int32_t relOffset;
                    std::memcpy(&relOffset, &sectionData[i], sizeof(int32_t));

                    // RIP-relative addressing: target = current_address + 4 + offset
                    uint64_t refAddr = section.address + i + 4 + relOffset;
                    if (refAddr == targetAddr)
                    {
                        return section.address + i;
                    }
                }
            }
        }
        return std::nullopt;
    }

    std::vector<uint64_t> ElfScanner::searchDataMaybeXrefAll(uint64_t targetAddr,
                                                             uint64_t start, uint64_t end) const
    {
        std::vector<uint64_t> results;

        if (!pImpl->initialized)
        {
            return results;
        }

        for (const auto &section : pImpl->sections)
        {
            if (section.address <= start && start < section.address + section.size)
            {
                if (section.offset + section.size > pImpl->fileData.size())
                {
                    continue;
                }

                size_t sectionStart = start - section.address;
                size_t searchLen = std::min(end - start, section.size - sectionStart);

                const uint8_t *sectionData = &pImpl->fileData[section.offset];

                for (size_t i = sectionStart; i <= sectionStart + searchLen - 4; i++)
                {
                    int32_t relOffset;
                    std::memcpy(&relOffset, &sectionData[i], sizeof(int32_t));

                    // RIP-relative addressing: target = current_address + 4 + offset
                    uint64_t refAddr = section.address + i + 4 + relOffset;
                    if (refAddr == targetAddr)
                    {
                        results.push_back(section.address + i);
                    }
                }
            }
        }
        return results;
    }

    std::vector<uint8_t> ElfScanner::getData(uint64_t addr, size_t size) const
    {
        std::vector<uint8_t> result;

        if (!pImpl->initialized)
        {
            return result;
        }

        for (const auto &section : pImpl->sections)
        {
            if (section.address <= addr && addr < section.address + section.size)
            {
                if (section.offset + section.size > pImpl->fileData.size())
                {
                    return result;
                }

                size_t offset = addr - section.address;
                size_t copySize = std::min(size, section.size - offset);

                result.resize(copySize);
                std::memcpy(result.data(), &pImpl->fileData[section.offset + offset], copySize);
                return result;
            }
        }
        return result;
    }

    std::optional<uint64_t> ElfScanner::searchCallMaybeXref(uint64_t targetAddr,
                                                             uint64_t start, uint64_t end) const
    {
        if (!pImpl->initialized)
        {
            return std::nullopt;
        }

        for (const auto &section : pImpl->sections)
        {
            if (section.address <= start && start < section.address + section.size)
            {
                if (section.offset + section.size > pImpl->fileData.size())
                {
                    continue;
                }

                size_t sectionStart = start - section.address;
                size_t searchLen = std::min(end - start, section.size - sectionStart);

                const uint8_t *sectionData = &pImpl->fileData[section.offset];

                // Search for CALL instructions (E8 xx xx xx xx - relative call)
                for (size_t i = sectionStart; i <= sectionStart + searchLen - 5; i++)
                {
                    // Quick check: only process if it's a CALL opcode (E8)
                    if (sectionData[i] != 0xE8)
                    {
                        continue;
                    }

                    int32_t relOffset;
                    std::memcpy(&relOffset, &sectionData[i + 1], sizeof(int32_t));

                    // RIP-relative addressing for CALL: target = current_address + 5 + offset
                    uint64_t refAddr = section.address + i + 5 + relOffset;
                    if (refAddr == targetAddr)
                    {
                        return section.address + i;
                    }
                }
            }
        }
        return std::nullopt;
    }

    std::vector<uint64_t> ElfScanner::searchCallMaybeXrefAll(uint64_t targetAddr,
                                                              uint64_t start, uint64_t end) const
    {
        std::vector<uint64_t> results;

        if (!pImpl->initialized)
        {
            return results;
        }

        for (const auto &section : pImpl->sections)
        {
            if (section.address <= start && start < section.address + section.size)
            {
                if (section.offset + section.size > pImpl->fileData.size())
                {
                    continue;
                }

                size_t sectionStart = start - section.address;
                size_t searchLen = std::min(end - start, section.size - sectionStart);

                const uint8_t *sectionData = &pImpl->fileData[section.offset];

                // Search for CALL instructions (E8 xx xx xx xx - relative call)
                for (size_t i = sectionStart; i <= sectionStart + searchLen - 5; i++)
                {
                    // Quick check: only process if it's a CALL opcode (E8)
                    if (sectionData[i] != 0xE8)
                    {
                        continue;
                    }

                    int32_t relOffset;
                    std::memcpy(&relOffset, &sectionData[i + 1], sizeof(int32_t));

                    // RIP-relative addressing for CALL: target = current_address + 5 + offset
                    uint64_t refAddr = section.address + i + 5 + relOffset;
                    if (refAddr == targetAddr)
                    {
                        results.push_back(section.address + i);
                    }
                }
            }
        }
        return results;
    }

} // namespace scanner
