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

option(RENHOOK_BUILD_TESTS "Build unit tests." NO)
option(RENHOOK_EXTRA_WARNINGS "Enable extra warnings." NO)
option(RENHOOK_TREAT_WARNINGS_AS_ERRORS "Treat compiler warnings as errors." NO)

include(cmake/ConfigureAndIncludeZydis.cmake)

if(RENHOOK_BUILD_TESTS)
  # Including Catch2 here so it won't be affected by the options set by "RENHOOK_EXTRA_WARNINGS" and
  # "RENHOOK_TREAT_WARNINGS_AS_ERRORS".
  include(cmake/ConfigureAndIncludeCatch2.cmake)
endif()

if(RENHOOK_EXTRA_WARNINGS)
  if(MSVC)
    add_compile_options(/W4)
  else()
    add_compile_options(-Wall -Wextra)
  endif()
endif()

if(RENHOOK_TREAT_WARNINGS_AS_ERRORS)
  if(MSVC)
    add_compile_options(/WX)
  else()
    add_compile_options(-Werror)
  endif()
endif()

# Create the library with all the necessary src / include files.
set(RENHOOK_HEADER_FILES
  include/renhook/renhook.hpp
  include/renhook/exceptions.hpp
  include/renhook/detail/core.hpp
)

set(RENHOOK_SRC_FILES
  src/exceptions.cpp
)

source_group(TREE "${PROJECT_SOURCE_DIR}/include/renhook" FILES ${RENHOOK_HEADER_FILES})
source_group(TREE "${PROJECT_SOURCE_DIR}/src" FILES ${RENHOOK_SRC_FILES})

add_library(RenHook STATIC ${RENHOOK_HEADER_FILES} ${RENHOOK_SRC_FILES})

target_include_directories(RenHook
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

target_link_libraries(RenHook PUBLIC Zydis)

# Add the tests if necessary.
if(RENHOOK_BUILD_TESTS)
  add_subdirectory(tests)
endif()
