cmake_minimum_required(VERSION 3.23)

project(RenHook LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if(NOT "${CMAKE_CXX_STANDARD}")
    set(CMAKE_CXX_STANDARD 14)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED YES)

option(RENHOOK_BUILD_TESTS "Build unit tests" OFF)

include(ConfigureAndIncludeZydis)

add_subdirectory(src)

if(RENHOOK_BUILD_TESTS)
    include(ConfigureAndIncludeCatch2)
    add_subdirectory(tests)
endif()
