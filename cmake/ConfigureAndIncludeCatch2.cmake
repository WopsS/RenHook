option(CATCH_INSTALL_DOCS OFF)
option(CATCH_INSTALL_EXTRAS OFF)

set(CATCH_CONFIG_WINDOWS_CRTDBG ON CACHE BOOL "")

add_subdirectory(deps/catch2)

if(PROJECT_IS_TOP_LEVEL)
  set_target_properties(Catch2 PROPERTIES FOLDER "Dependencies")
  set_target_properties(Catch2WithMain PROPERTIES FOLDER "Dependencies")
endif()

mark_as_advanced(
  CATCH_CONFIG_ANDROID_LOGWRITE
  CATCH_CONFIG_BAZEL_SUPPORT
  CATCH_CONFIG_COLOUR_WIN32
  CATCH_CONFIG_CONSOLE_WIDTH
  CATCH_CONFIG_COUNTER
  CATCH_CONFIG_CPP11_TO_STRING
  CATCH_CONFIG_CPP17_BYTE
  CATCH_CONFIG_CPP17_OPTIONAL
  CATCH_CONFIG_CPP17_STRING_VIEW
  CATCH_CONFIG_CPP17_UNCAUGHT_EXCEPTIONS
  CATCH_CONFIG_CPP17_VARIANT
  CATCH_CONFIG_DEFAULT_REPORTER
  CATCH_CONFIG_DISABLE
  CATCH_CONFIG_DISABLE_EXCEPTIONS
  CATCH_CONFIG_DISABLE_EXCEPTIONS_CUSTOM_HANDLER
  CATCH_CONFIG_DISABLE_STRINGIFICATION
  CATCH_CONFIG_ENABLE_ALL_STRINGMAKERS
  CATCH_CONFIG_ENABLE_OPTIONAL_STRINGMAKER
  CATCH_CONFIG_ENABLE_PAIR_STRINGMAKER
  CATCH_CONFIG_ENABLE_TUPLE_STRINGMAKER
  CATCH_CONFIG_ENABLE_VARIANT_STRINGMAKER
  CATCH_CONFIG_EXPERIMENTAL_REDIRECT
  CATCH_CONFIG_FAST_COMPILE
  CATCH_CONFIG_GLOBAL_NEXTAFTER
  CATCH_CONFIG_NOSTDOUT
  CATCH_CONFIG_NO_ANDROID_LOGWRITE
  CATCH_CONFIG_NO_BAZEL_SUPPORT
  CATCH_CONFIG_NO_COLOUR_WIN32
  CATCH_CONFIG_NO_COUNTER
  CATCH_CONFIG_NO_CPP11_TO_STRING
  CATCH_CONFIG_NO_CPP17_BYTE
  CATCH_CONFIG_NO_CPP17_OPTIONAL
  CATCH_CONFIG_NO_CPP17_STRING_VIEW
  CATCH_CONFIG_NO_CPP17_UNCAUGHT_EXCEPTIONS
  CATCH_CONFIG_NO_CPP17_VARIANT
  CATCH_CONFIG_NO_GLOBAL_NEXTAFTER
  CATCH_CONFIG_NO_POSIX_SIGNALS
  CATCH_CONFIG_NO_USE_ASYNC
  CATCH_CONFIG_NO_WCHAR
  CATCH_CONFIG_NO_WINDOWS_SEH
  CATCH_CONFIG_POSIX_SIGNALS
  CATCH_CONFIG_PREFIX_ALL
  CATCH_CONFIG_USE_ASYNC
  CATCH_CONFIG_WCHAR
  CATCH_CONFIG_WINDOWS_CRTDBG
  CATCH_CONFIG_WINDOWS_SEH
  CATCH_DEVELOPMENT_BUILD
  CATCH_INSTALL_DOCS
  CATCH_INSTALL_EXTRAS
)
