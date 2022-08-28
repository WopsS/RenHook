set(
  RENHOOK_TESTS_SRC_FILES
    exceptions.cpp
)

source_group(
  TREE "${CMAKE_CURRENT_SOURCE_DIR}"
  FILES ${RENHOOK_TESTS_SRC_FILES}
)

add_executable(Tests ${RENHOOK_TESTS_SRC_FILES})

target_include_directories(Tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

target_compile_options(
  Tests
    PRIVATE
      ${RENHOOK_EXTRA_WARNINGS_FLAGS}
      ${RENHOOK_TREAT_WARNINGS_AS_ERRORS_FLAG}
)

target_link_libraries(
  Tests
    PRIVATE
      RenHook
      Catch2::Catch2WithMain
)
