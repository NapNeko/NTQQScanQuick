cmake_minimum_required(VERSION 3.14)
project(PeRedirect LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ==================== 极致性能优化配置 ====================
# 启用链接时优化(LTO/IPO) - 跨编译单元优化
include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
if(ipo_supported)
    message(STATUS "IPO/LTO enabled")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
    message(WARNING "IPO/LTO not supported: ${ipo_error}")
endif()


# 配置Capstone构建选项 - 支持x86和ARM64
set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "Build static library")
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "Build shared library")
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "Build tests")
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "Build cstool")
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "x86 support")
set(CAPSTONE_ARM_SUPPORT OFF CACHE BOOL "ARM support")
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "ARM64 support")
set(CAPSTONE_MIPS_SUPPORT OFF CACHE BOOL "MIPS support")
set(CAPSTONE_PPC_SUPPORT OFF CACHE BOOL "PowerPC support")
set(CAPSTONE_SPARC_SUPPORT OFF CACHE BOOL "Sparc support")
set(CAPSTONE_SYSZ_SUPPORT OFF CACHE BOOL "SystemZ support")
set(CAPSTONE_XCORE_SUPPORT OFF CACHE BOOL "XCore support")
set(CAPSTONE_M68K_SUPPORT OFF CACHE BOOL "M68K support")
set(CAPSTONE_TMS320C64X_SUPPORT OFF CACHE BOOL "TMS320C64x support")
set(CAPSTONE_M680X_SUPPORT OFF CACHE BOOL "M680x support")
set(CAPSTONE_EVM_SUPPORT OFF CACHE BOOL "EVM support")

# 优先查找系统安装的Capstone
find_package(capstone QUIET)

if(NOT capstone_FOUND)
    message(STATUS "System Capstone not found, using FetchContent...")
    
    # 使用FetchContent下载Capstone (仅在未找到时)
    include(FetchContent)
    
    # 设置基础目录以避免重复下载
    set(FETCHCONTENT_BASE_DIR "${CMAKE_SOURCE_DIR}/.cache" CACHE PATH "FetchContent base directory")
    
    FetchContent_Declare(
        capstone
        GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
        GIT_TAG        5.0.1
        GIT_SHALLOW    TRUE
        GIT_PROGRESS   TRUE
    )
    
    # 使用 FetchContent_MakeAvailable 替代已弃用的 FetchContent_Populate
    message(STATUS "Downloading and building Capstone...")
    FetchContent_MakeAvailable(capstone)
else()
    message(STATUS "Using system Capstone")
endif()

# 添加包含目录
include_directories(${CMAKE_SOURCE_DIR}/include)

# Scanner库 - 包含所有扫描器
add_library(scanner STATIC
    src/ElfScanner.cpp
    src/ElfScannerArm64.cpp
    src/PeScanner.cpp
    src/helper.cpp
)

target_include_directories(scanner PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(scanner PUBLIC capstone)

# 主可执行文件
add_executable(PeRedirect main.cpp)
target_link_libraries(PeRedirect PRIVATE scanner)

install(DIRECTORY include/ DESTINATION include)
install(TARGETS scanner DESTINATION lib)
