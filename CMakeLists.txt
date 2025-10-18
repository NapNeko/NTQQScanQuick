cmake_minimum_required(VERSION 3.14)
project(PeRedirect LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 启用链接时优化(LTO/IPO) - 跨编译单元优化
include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
if(ipo_supported)
    message(STATUS "IPO/LTO enabled")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
    message(WARNING "IPO/LTO not supported: ${ipo_error}")
endif()


# 添加包含目录
include_directories(${CMAKE_SOURCE_DIR}/include)

add_library(scanner STATIC
    src/ElfScanner.cpp
    src/PeScanner.cpp
    src/helper.cpp
)

target_include_directories(scanner PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)


add_executable(PeRedirect main.cpp)
target_link_libraries(PeRedirect PRIVATE scanner)

install(DIRECTORY include/ DESTINATION include)
install(TARGETS scanner DESTINATION lib)
