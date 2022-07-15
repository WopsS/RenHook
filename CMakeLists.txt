cmake_minimum_required(VERSION 3.21)

project(RenHook LANGUAGES CXX)

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 14)
  set(CMAKE_CXX_STANDARD_REQUIRED YES)
elseif(CMAKE_CXX_STANDARD LESS 14)
  message(FATAL_ERROR "RenHook requires C++14 or higher.")
endif()

if(PROJECT_IS_TOP_LEVEL)
  set_property(GLOBAL PROPERTY USE_FOLDERS YES)
endif()

option(RENHOOK_BUILD_TESTS "Build unit tests" NO)

include(cmake/ConfigureAndIncludeZydis.cmake)

# Set the custom compile options to enable more warnings and treat them as errors.
set(RENHOOK_COMPILE_OPTIONS /W4 /WX)

# Create the library with all the necessary src / include files.
set(RENHOOK_HEADER_FILES
  include/renhook/renhook.hpp
)

set(RENHOOK_SRC_FILES
  src/gitkeep.cpp
)

source_group(TREE "${PROJECT_SOURCE_DIR}/include/renhook" FILES ${RENHOOK_HEADER_FILES})
source_group(TREE "${PROJECT_SOURCE_DIR}/src" FILES ${RENHOOK_SRC_FILES})

add_library(RenHook STATIC ${RENHOOK_SRC_FILES} ${RENHOOK_HEADER_FILES})

target_include_directories(RenHook
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

target_compile_options(RenHook PRIVATE ${RENHOOK_COMPILE_OPTIONS})
target_link_libraries(RenHook PUBLIC Zydis)

# Add the tests if necessary.
if(RENHOOK_BUILD_TESTS)
  include(cmake/ConfigureAndIncludeCatch2.cmake)
  add_subdirectory(tests)
endif()
