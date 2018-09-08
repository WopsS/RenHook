add_library(renhook STATIC "")

math(EXPR PROJECT_VERSION_INT "${PROJECT_VERSION_MAJOR} * 10000 + ${PROJECT_VERSION_MINOR} * 100 + ${PROJECT_VERSION_PATCH}")
configure_file("renhook/version.hpp.in" "${CMAKE_CURRENT_SOURCE_DIR}/renhook/version.hpp" @ONLY)

file(GLOB_RECURSE HEADERS renhook/*.hpp)
file(GLOB_RECURSE SOURCES renhook/*.cpp)

source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/renhook" FILES ${HEADERS} ${SOURCES})

target_include_directories(renhook PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_sources(renhook PRIVATE ${HEADERS} ${SOURCES})
target_link_libraries(renhook PRIVATE Zydis)