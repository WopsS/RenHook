cmake_minimum_required(VERSION 3.21)

project(
  RenHook
  VERSION 0.1.0
  LANGUAGES CXX
)

# -----------------------------------------------------------------------------
# General configuration / options / variables
# -----------------------------------------------------------------------------
if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 14)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
elseif(CMAKE_CXX_STANDARD LESS 14)
  message(FATAL_ERROR "RenHook requires C++14 or higher.")
endif()

if(PROJECT_IS_TOP_LEVEL)
  set_property(GLOBAL PROPERTY USE_FOLDERS ON)
endif()

include(cmake/ConfigureAndIncludeZydis.cmake)

option(RENHOOK_USE_PCH "Use precompiled headers to speed up compilation time." OFF)

set(RENHOOK_CMAKE_DIR "${PROJECT_SOURCE_DIR}/cmake")
set(RENHOOK_CMAKE_TEMPLATES_DIR "${RENHOOK_CMAKE_DIR}/templates")
set(RENHOOK_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/include/")

# -----------------------------------------------------------------------------
# Options related to warnings
# -----------------------------------------------------------------------------
if(PROJECT_IS_TOP_LEVEL)
  option(RENHOOK_EXTRA_WARNINGS "Enable extra warnings." OFF)
  if(RENHOOK_EXTRA_WARNINGS)
    if(MSVC)
      set(RENHOOK_EXTRA_WARNINGS_FLAGS /W4)
    else()
      set(RENHOOK_EXTRA_WARNINGS_FLAGS -Wall -Wextra)
    endif()
  endif()

  option(RENHOOK_TREAT_WARNINGS_AS_ERRORS "Treat compiler warnings as errors." OFF)
  if(RENHOOK_TREAT_WARNINGS_AS_ERRORS)
    if(MSVC)
      set(RENHOOK_TREAT_WARNINGS_AS_ERRORS_FLAG /WX)
    else()
      set(RENHOOK_TREAT_WARNINGS_AS_ERRORS_FLAG -Werror)
    endif()
  endif()
endif()

# -----------------------------------------------------------------------------
# Main library
# -----------------------------------------------------------------------------
set(
  RENHOOK_HEADER_FILES
    include/renhook/renhook.hpp
    include/renhook/exceptions.hpp
    include/renhook/detail/core.hpp
)

set(
  RENHOOK_SRC_FILES
    src/exceptions.cpp
)

get_property(RENHOOK_USE_FOLDERS GLOBAL PROPERTY USE_FOLDERS)
if(RENHOOK_USE_FOLDERS)
  source_group(cmake REGULAR_EXPRESSION cmake_pch.*)

  source_group(
    TREE "${RENHOOK_INCLUDE_DIR}/renhook"
    FILES ${RENHOOK_HEADER_FILES}
  )

  source_group(
    TREE "${PROJECT_SOURCE_DIR}/src"
    FILES ${RENHOOK_SRC_FILES}
  )
endif()

add_library(
  RenHook STATIC
  ${RENHOOK_HEADER_FILES}
  ${RENHOOK_SRC_FILES}
)
add_library(RenHook::RenHook ALIAS RenHook)

target_include_directories(
  RenHook
    PUBLIC
      "$<BUILD_INTERFACE:${RENHOOK_INCLUDE_DIR}>"
      "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_compile_options(
  RenHook
    PRIVATE
      ${RENHOOK_EXTRA_WARNINGS_FLAGS}
      ${RENHOOK_TREAT_WARNINGS_AS_ERRORS_FLAG}
)

target_link_libraries(RenHook PUBLIC Zydis)

if(RENHOOK_USE_PCH)
    set(RENHOOK_PCH_FILE "${PROJECT_BINARY_DIR}/renhook_pch.hpp")
    set(RENHOOK_PCH_FILE_IN "${RENHOOK_CMAKE_TEMPLATES_DIR}/pch.hpp.in")

    configure_file(
      "${RENHOOK_PCH_FILE_IN}"
      "${RENHOOK_PCH_FILE}"
      @ONLY
    )

    target_precompile_headers(RenHook PRIVATE "${RENHOOK_PCH_FILE}")
endif()

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
if(PROJECT_IS_TOP_LEVEL)
  option(RENHOOK_BUILD_TESTS "Build unit tests." OFF)
  if(RENHOOK_BUILD_TESTS)
    include(cmake/ConfigureAndIncludeCatch2.cmake)
    add_subdirectory(tests)
  endif()
endif()

# -----------------------------------------------------------------------------
# Install
# -----------------------------------------------------------------------------
if(NOT CMAKE_SKIP_INSTALL_RULES)
  option(RENHOOK_INSTALL "Generate the install target." ${PROJECT_IS_TOP_LEVEL})
  if(RENHOOK_INSTALL)
    include(CMakePackageConfigHelpers)
    include(GNUInstallDirs)

    set(RENHOOK_EXPORT_NAME RenHook)
    set(RENHOOK_EXPORT_TARGETS "${RENHOOK_EXPORT_NAME}Targets")

    set(RENHOOK_CMAKE_CONFIG_DIR "${PROJECT_BINARY_DIR}")

    set(RENHOOK_CMAKE_PROJECT_CONFIG_FILE "${RENHOOK_CMAKE_CONFIG_DIR}/${RENHOOK_EXPORT_NAME}Config.cmake")
    set(RENHOOK_CMAKE_PROJECT_CONFIG_FILE_IN "${RENHOOK_CMAKE_TEMPLATES_DIR}/${RENHOOK_EXPORT_NAME}Config.cmake.in")
    set(RENHOOK_CMAKE_PROJECT_VERSION_FILE "${RENHOOK_CMAKE_CONFIG_DIR}/${RENHOOK_EXPORT_NAME}ConfigVersion.cmake")

    set(RENHOOK_INSTALL_CONFIG_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/${RENHOOK_EXPORT_NAME}")

    configure_package_config_file(
      "${RENHOOK_CMAKE_PROJECT_CONFIG_FILE_IN}"
      "${RENHOOK_CMAKE_PROJECT_CONFIG_FILE}"
      INSTALL_DESTINATION "${RENHOOK_INSTALL_CONFIG_DIR}"
    )

    write_basic_package_version_file(
      "${RENHOOK_CMAKE_PROJECT_VERSION_FILE}"
      VERSION ${PROJECT_VERSION}
      COMPATIBILITY SameMajorVersion
    )

    install(
      DIRECTORY "${RENHOOK_INCLUDE_DIR}/"
      DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    )

    install(
      TARGETS RenHook
      EXPORT ${RENHOOK_EXPORT_TARGETS}
      INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
      PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
      LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
      ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
      RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    )

    install(
      FILES
        "${RENHOOK_CMAKE_PROJECT_CONFIG_FILE}"
        "${RENHOOK_CMAKE_PROJECT_VERSION_FILE}"
      DESTINATION "${RENHOOK_INSTALL_CONFIG_DIR}"
    )

    install(
      EXPORT ${RENHOOK_EXPORT_TARGETS}
      NAMESPACE RenHook::
      DESTINATION "${RENHOOK_INSTALL_CONFIG_DIR}"
    )

    # -------------------------------------------------------------------------
    # pkg-config
    # -------------------------------------------------------------------------
    set(RENHOOK_PKG_CONFIG_FILE "${RENHOOK_CMAKE_CONFIG_DIR}/${RENHOOK_EXPORT_NAME}.pc")
    set(RENHOOK_PKG_CONFIG_FILE_IN "${RENHOOK_CMAKE_TEMPLATES_DIR}/${RENHOOK_EXPORT_NAME}.pc.in")
    set(RENHOOK_INSTALL_PKG_CONFIG_DIR "${RENHOOK_INSTALL_CONFIG_DIR}/pkgconfig")

    if (IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
        set(RENHOOK_PKG_CONFIG_INCLUDE_DIR "${CMAKE_INSTALL_INCLUDEDIR}")
    else()
        set(RENHOOK_PKG_CONFIG_INCLUDE_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}")
    endif()

    if (IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
        set(RENHOOK_PKG_CONFIG_LIB_DIR "${CMAKE_INSTALL_LIBDIR}")
    else()
        set(RENHOOK_PKG_CONFIG_LIB_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
    endif()

    configure_file(
      "${RENHOOK_PKG_CONFIG_FILE_IN}"
      "${RENHOOK_PKG_CONFIG_FILE}"
      @ONLY
    )

    install(
      FILES "${RENHOOK_PKG_CONFIG_FILE}"
      DESTINATION "${RENHOOK_INSTALL_PKG_CONFIG_DIR}"
    )
  endif()
endif()
