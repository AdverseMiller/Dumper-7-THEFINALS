cmake_minimum_required(VERSION 3.15...4.0)

# Ninja generator does not support platform specification
if(CMAKE_GENERATOR MATCHES "Ninja")
    # Remove all variables related to platform
    unset(CMAKE_GENERATOR_PLATFORM CACHE)
    unset(CMAKE_GENERATOR_PLATFORM)
    unset(CMAKE_VS_PLATFORM_NAME CACHE)
    unset(CMAKE_VS_PLATFORM_NAME)
    message(STATUS "Using Ninja generator - platform specification disabled")
endif()

project(Dumper-7 LANGUAGES CXX C)

include(${CMAKE_SOURCE_DIR}/cmake/Common.cmake)
include(FetchContent)

# Capstone's packaging configuration assumes this is non-empty. CMake leaves it
# unset when MinGW is selected directly instead of through a toolchain file.
if(NOT CMAKE_SYSTEM_PROCESSOR)
    set(CMAKE_SYSTEM_PROCESSOR x86_64)
endif()

# Discovery uses Capstone inside the DLL to evaluate protected accessors by
# instruction semantics instead of tying recovery to one compiler byte pattern.
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "" FORCE)
set(CAPSTONE_INSTALL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
FetchContent_Declare(capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG 5.0.7
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(capstone)

# Source files - automatic search for all source files
file(GLOB_RECURSE CPP_SOURCES 
    "Dumper/*.cpp"
    "Dumper/*.cxx"
    "Dumper/*.cc"
    "Dumper/*.c"
)

add_library(${PROJECT_NAME} SHARED ${CPP_SOURCES})

target_link_libraries(${PROJECT_NAME} PRIVATE capstone_static)

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
# Dumper
    ${CMAKE_SOURCE_DIR}/Dumper

    # Engine
    ${CMAKE_SOURCE_DIR}/Dumper/Engine
    ${CMAKE_SOURCE_DIR}/Dumper/Engine/Private
    ${CMAKE_SOURCE_DIR}/Dumper/Engine/Private/OffsetFinder
    ${CMAKE_SOURCE_DIR}/Dumper/Engine/Private/Unreal

    # Engine Public
    ${CMAKE_SOURCE_DIR}/Dumper/Engine/Public
    ${CMAKE_SOURCE_DIR}/Dumper/Engine/Public/OffsetFinder
    ${CMAKE_SOURCE_DIR}/Dumper/Engine/Public/Unreal

    # Generator
    ${CMAKE_SOURCE_DIR}/Dumper/Generator
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Private
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Private/Generators
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Private/Managers
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Private/Wrappers

    # Generator Public
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Public
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Public/Generators
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Public/Managers
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Public/Wrappers

    # Platform
    ${CMAKE_SOURCE_DIR}/Dumper/Platform
    ${CMAKE_SOURCE_DIR}/Dumper/Platform/Private

    # Platform Public
    ${CMAKE_SOURCE_DIR}/Dumper/Platform/Public

    # Utils
    ${CMAKE_SOURCE_DIR}/Dumper/Utils
    ${CMAKE_SOURCE_DIR}/Dumper/Utils/Compression
    ${CMAKE_SOURCE_DIR}/Dumper/Utils/Dumpspace
    ${CMAKE_SOURCE_DIR}/Dumper/Utils/Encoding
    ${CMAKE_SOURCE_DIR}/Dumper/Utils/Json
)

# Compiler definitions
target_compile_definitions(${PROJECT_NAME} PRIVATE
    $<$<CONFIG:Debug>:_DEBUG>
    $<$<CONFIG:Release>:NDEBUG>
    _CONSOLE
    WIN32
)

# Set Windows subsystem
set_target_properties(${PROJECT_NAME} PROPERTIES
    WINDOWS_EXPORT_ALL_SYMBOLS ON
    VS_GLOBAL_KEYWORD "Win32Proj"
)
