add_library(RenHook STATIC "")

math(EXPR PROJECT_VERSION_INT "${PROJECT_VERSION_MAJOR} * 10000 + ${PROJECT_VERSION_MINOR} * 100 + ${PROJECT_VERSION_PATCH}")
configure_file("renhook/version.hpp.in" "${CMAKE_CURRENT_SOURCE_DIR}/renhook/version.hpp" @ONLY)

file(GLOB_RECURSE HEADERS renhook/*.hpp)
file(GLOB_RECURSE SOURCES renhook/*.cpp)

source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/renhook" FILES ${HEADERS} ${SOURCES})

target_include_directories(RenHook PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_sources(RenHook PRIVATE ${HEADERS} ${SOURCES})
target_link_libraries(RenHook PUBLIC Zydis)
